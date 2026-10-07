-- access_by_lua for customer traffic: host → zone, refusals, the cache
-- key, and the signed S3 origin request.
--
-- Nothing from the client reaches the origin except the object path:
-- the location sends no client header, no body and no query string
-- upstream. The origin host is the measured OpenResty config's, never
-- the feed's; the feed only names the bucket and prefix.
local cjson = require("cjson.safe")
local docs = require("hippius_cdn.docs")
local settings = require("hippius_cdn.settings")
local sigv4 = require("hippius_cdn.sigv4")
local util = require("hippius_cdn.util")

local M = {}

local null = cjson.null

-- Answer without touching the cache or the origin: never billable.
local function refuse(status)
    ngx.ctx.billable = false
    return ngx.exit(status)
end

local function path_blocked(blocks, zone_id, path)
    for _, scope in ipairs({ zone_id, "*" }) do
        local exact = blocks.exact[scope]
        if exact and exact[path] then
            return true
        end
        for _, prefix in ipairs(blocks.prefixes[scope] or {}) do
            if path:sub(1, #prefix) == prefix then
                return true
            end
        end
    end
    return false
end

-- Resolve the zone for `host` (exact name, then its wildcard).
function M.zone_for(cfg, host)
    local zid = cfg.hostnames[host]
    if zid then
        return zid
    end
    local wc = util.wildcard_of(host)
    return wc and cfg.hostnames[wc] or nil
end

-- The S3 object URI for a request path: "/<bucket>/<prefix><path>",
-- percent-encoded. nil for the bucket root (that would list it).
function M.origin_uri(origin, path)
    local prefix = origin.prefix
    if prefix == nil or prefix == null then
        prefix = ""
    end
    local key = prefix .. path:sub(2)
    if key == "" then
        return nil
    end
    return util.encode_path("/" .. origin.bucket .. "/" .. key)
end

-- Credentials end up in the origin request: printable ASCII, no spaces.
local function header_safe(v)
    return type(v) == "string" and #v > 0 and #v <= 4096 and not v:find("[^\33-\126]")
end

-- The origin URI, presigned when the zone has credentials (private
-- bucket) and bare otherwise (public bucket). nil when the credentials
-- are unusable.
local function signed_uri(var, zone_secrets, origin, uri)
    local creds = zone_secrets and zone_secrets.s3_credentials
    if not creds then
        return uri
    end
    local c = cjson.decode(creds)
    if type(c) ~= "table" or not header_safe(c.access_key_id) or not header_safe(c.secret_access_key)
        or (c.session_token ~= nil and c.session_token ~= null and not header_safe(c.session_token)) then
        return nil
    end
    local region = origin.region
    if region == nil or region == null then
        region = settings.s3_region
    end
    local token = c.session_token
    if token == null or token == "" then
        token = nil
    end
    return uri .. "?" .. sigv4.presign({
        method = "GET",
        uri = uri,
        host = var.hippius_s3_host,
        amz_date = sigv4.amz_date(ngx.time()),
        expires = settings.presign_expires,
        region = region,
        service = "s3",
        access_key = c.access_key_id,
        secret_key = c.secret_access_key,
        session_token = token,
    })
end

function M.access()
    local ctx, var = ngx.ctx, ngx.var
    local store = docs.get("config")
    if not store then
        return refuse(503)
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
        return refuse(405)
    end
    local host = var.host
    if not util.valid_host(host) then
        return refuse(400)
    end
    -- On TLS the Host must be the name the handshake was for: no
    -- fronting one zone's hostname through another's certificate.
    if var.https == "on" then
        local sni = var.ssl_server_name
        if sni == nil or sni == "" or sni:lower() ~= host then
            return refuse(421)
        end
    end
    local zone_id = M.zone_for(store, host)
    if not zone_id then
        return refuse(421)
    end
    ctx.zone = zone_id
    local zone = store.doc.zones[zone_id]
    if store.blocks.hosts[host] then
        return refuse(451)
    end
    if zone.state == "suspended" then
        return refuse(403)
    end
    if zone.state == "paused" or not zone.serving then
        return refuse(503)
    end
    local path = var.uri
    if not util.valid_path(path) then
        return refuse(400)
    end
    if path_blocked(store.blocks, zone_id, path) then
        return refuse(451)
    end
    local settings_doc = type(zone.settings) == "table" and zone.settings or {}
    if var.scheme == "http" and settings_doc.redirect_https ~= false then
        ctx.billable = true
        return ngx.redirect("https://" .. host .. var.request_uri, 301)
    end
    local uri = M.origin_uri(zone.origin, path)
    if not uri then
        return refuse(404)
    end
    -- Compression hook: gzip runs in the response filter only when the
    -- zone list enables it; brotli would be switched on here once the
    -- build ships ngx_brotli (the agent refuses it until then).
    if not store.compression.gzip then
        ngx.req.clear_header("Accept-Encoding")
    end
    local secrets = docs.get("secrets")
    local origin_uri = signed_uri(var, secrets and secrets.doc.zones[zone_id], zone.origin, uri)
    if not origin_uri then
        ngx.log(ngx.CRIT, "hippius-cdn: zone ", zone_id, " has unusable s3 credentials")
        return refuse(503)
    end
    var.hippius_origin_uri = origin_uri
    var.hippius_cache_key = ngx.md5(util.cache_key_material(zone_id, store.purges[zone_id], path))
    ctx.billable = true
end

-- Error bodies: an origin error (S3 XML naming the bucket, the key, the
-- access key id) or nginx's own error page never reaches the client.
-- Every status >= 400 gets a short generic body instead.
function M.header_filter()
    -- An empty object: S3 answers the first slice's ranged GET with 416
    -- and "Content-Range: bytes */0". Without a client Range, that is an
    -- empty 200.
    if ngx.status == 416 and not ngx.is_subrequest and ngx.var.http_range == nil
        and ngx.header["Content-Range"] == "bytes */0" then
        ngx.status = 200
        ngx.header["Content-Range"] = nil
        ngx.header["Content-Length"] = 0
        ngx.ctx.empty_body = true
        return
    end
    if ngx.status >= 400 then
        ngx.ctx.generic_body = true
        ngx.header["Content-Length"] = nil
        ngx.header["Content-Encoding"] = nil
        ngx.header["Content-Type"] = "text/plain"
        ngx.header["Cache-Control"] = "no-store"
    end
end

function M.body_filter()
    if ngx.ctx.empty_body then
        ngx.arg[1] = nil
        return
    end
    if not ngx.ctx.generic_body then
        return
    end
    if ngx.arg[2] then
        ngx.arg[1] = tostring(ngx.status) .. "\n"
    else
        ngx.arg[1] = nil
    end
end

return M
