-- access_by_lua for customer traffic: host → zone, refusals, the cache
-- key, and the signed S3 origin request.
--
-- Nothing from the client reaches the origin except the object path:
-- the location sends no client header, no body and no query string
-- upstream. The origin host is the measured OpenResty config's, never
-- the feed's; the feed only names the bucket and prefix.
local cjson = require("cjson.safe")
local docs = require("hippius_cdn.docs")
local mime = require("hippius_cdn.mime")
local rules = require("hippius_cdn.rules")
local limits = require("hippius_cdn.limits")
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

-- A zone's `s3_credentials` secret: the JSON the backend sealed,
-- {"access_key_id": ..., "secret": ...} (the read-only SubToken), with
-- `secret_access_key` accepted for `secret` and an optional
-- `session_token`. Returns the normalised table, false when the zone has
-- none (public bucket), or nil and the reason (a field name, never a
-- value).
function M.s3_credentials(zone_secrets)
    local raw = zone_secrets and zone_secrets.s3_credentials
    if not raw then
        return false
    end
    local c = cjson.decode(raw)
    if type(c) ~= "table" then
        return nil, "s3_credentials is not a JSON object"
    end
    if not header_safe(c.access_key_id) then
        return nil, "access_key_id missing or invalid"
    end
    local secret = c.secret_access_key
    if secret == nil or secret == null then
        secret = c.secret
    end
    if not header_safe(secret) then
        return nil, "secret missing or invalid"
    end
    local token = c.session_token
    if token == null or token == "" then
        token = nil
    end
    if token ~= nil and not header_safe(token) then
        return nil, "session_token invalid"
    end
    return { access_key_id = c.access_key_id, secret_access_key = secret, session_token = token }
end

-- One line per zone and ceiling a minute (per worker) while a zone is held
-- at its ceiling.
local limit_logged = {}

-- Body bytes a request adds up before counting them (see body_filter).
local ACCOUNT_BATCH = 65536

function M.should_log_limit(zone_id, which, now)
    local key = zone_id .. "\0" .. which
    local last = limit_logged[key]
    if last and now - last < 60 then
        return false
    end
    limit_logged[key] = now
    return true
end

-- One CRIT line per zone and reason a minute (per worker): a busy zone
-- with broken credentials must not flood the journal.
local CRED_LOG_EVERY = 60
local cred_logged = {}

function M.should_log_credentials(zone_id, why, now)
    local key = zone_id .. "\0" .. why
    local last = cred_logged[key]
    if last and now - last < CRED_LOG_EVERY then
        return false
    end
    cred_logged[key] = now
    return true
end

-- The origin URI, presigned when the zone has credentials (private
-- bucket) and bare otherwise (public bucket). nil and the reason when the
-- credentials are unusable.
local function signed_uri(var, zone_secrets, origin, uri)
    local c, why = M.s3_credentials(zone_secrets)
    if c == false then
        return uri
    end
    if not c then
        return nil, why
    end
    local region = origin.region
    if region == nil or region == null then
        region = settings.s3_region
    end
    local token = c.session_token
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
    -- The zone's ceilings (per node): over one, new requests get 503.
    local lim = store.limits and store.limits[zone_id]
    if lim then
        local ok, which = limits.admit(ngx.shared.hippius_limits, zone_id, lim, ngx.time())
        if not ok then
            if M.should_log_limit(zone_id, which, ngx.now()) then
                -- CRIT: this location logs nothing below (presigned URLs).
                ngx.log(ngx.CRIT, "hippius-cdn: zone ", zone_id, " over its ", which, " ceiling: 503")
            end
            -- When to come back: the request window is one second, the
            -- bandwidth one looks back two. A ceiling of 0 never clears;
            -- no Retry-After then.
            if lim[which] ~= 0 then
                ngx.ctx.retry_after = which == "rps" and "1" or "2"
            end
            return refuse(503)
        end
    end
    var.hippius_zone = zone_id
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
        ctx.redirect = true
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
    local origin_uri, why = signed_uri(var, secrets and secrets.doc.zones[zone_id], zone.origin, uri)
    if not origin_uri then
        if M.should_log_credentials(zone_id, why, ngx.now()) then
            ngx.log(ngx.CRIT, "hippius-cdn: zone ", zone_id, " has unusable s3 credentials: ", why)
        end
        return refuse(503)
    end
    var.hippius_origin_uri = origin_uri
    -- The zone's first matching cache rule, on the decoded path (none:
    -- the defaults).
    local decision = rules.decide(rules.match(store.rules and store.rules[zone_id], path))
    if M.client_headers_bypass(zone.origin, var) then
        decision.bypass, decision.skip_lookup = true, true
    end
    ctx.decision = decision
    var.hippius_edge_ttl = rules.edge_header(decision)
    if decision.skip_lookup then
        var.hippius_cache_bypass = "1"
    end
    if decision.bypass then
        var.hippius_no_store = "1"
    end
    var.hippius_cache_key = ngx.md5(util.cache_key_material(zone_id, store.purges[zone_id], path,
        rules.query_key(decision.qs, var.args)))
    ctx.billable = true
end

-- Requests carrying Authorization or a cookie bypass the cache only for
-- origins that receive client headers (contract C.4, amended). An S3 origin
-- never sees one (the node presigns its own request), so its response
-- cannot depend on one and such requests are cached like any other. The
-- one place to change when an origin kind that forwards client headers
-- arrives.
function M.client_headers_bypass(origin, var)
    if type(origin) == "table" and origin.type == "s3" then
        return false
    end
    return var.http_authorization ~= nil or var.http_cookie ~= nil
end

-- The client's Cache-Control for a 2xx/304 under `decision` (nil: no
-- rule), given the edge TTL the response was stored with (`stored_ttl`,
-- nil when unknown), as the backend contract states it: the rule's
-- browser_ttl when it sets a number; else `no-store` when the request
-- skips the cache (bypass or edge_ttl 0) or the edge TTL in effect is 0
-- (the origin forbade caching under "origin"); else the edge TTL in effect.
function M.client_cache_control(decision, stored_ttl)
    if decision and decision.browser then
        return "public, max-age=" .. decision.browser
    end
    if decision and decision.skip_lookup then
        return "no-store"
    end
    local max_age = stored_ttl or settings.default_ttl
    if max_age == 0 then
        return "no-store"
    end
    return "public, max-age=" .. max_age
end

-- Internal origin server (unix socket, behind the cache): the edge TTL
-- the caching location stores the response for, as X-Accel-Expires, from
-- the rule's decision sent in X-Hippius-Edge-TTL ("default", "origin" or
-- seconds). The origin's own X-Accel-* never get here (hidden). Only
-- 200/206/304: a 404 keeps proxy_cache_valid's minute, errors are never
-- stored. X-Hippius-TTL repeats the figure for the client's Cache-Control;
-- it is stored with the response and dropped before the client.
function M.origin_ttl_header(edge, status, cache_control, expires, now)
    if status ~= 200 and status ~= 206 and status ~= 304 then
        return nil
    end
    local seconds
    if edge == "origin" then
        seconds = rules.origin_ttl(cache_control, expires, now)
    else
        seconds = tonumber(edge)
        if seconds and (seconds < 0 or seconds > rules.MAX_TTL or seconds % 1 ~= 0) then
            seconds = nil
        end
    end
    return seconds or settings.default_ttl
end

function M.origin_header_filter()
    local var = ngx.var
    local ttl = M.origin_ttl_header(var.http_x_hippius_edge_ttl or "default", ngx.status,
        var.upstream_http_cache_control, var.upstream_http_expires, ngx.time())
    if ttl then
        ngx.header["X-Accel-Expires"] = ttl
        ngx.header["X-Hippius-TTL"] = ttl
    end
end

-- Error bodies: an origin error (S3 XML naming the bucket, the key, the
-- access key id) or nginx's own error page never reaches the client.
-- Every status >= 400 gets a short generic body instead.
-- The only response headers a client sees from the origin (lower case).
-- Everything else the origin sends (x-hippius-*, x-amz-*, Server,
-- Set-Cookie, Expires, Vary, Age...) is dropped. Cache-Control is ours,
-- computed below; X-Cache, Vary (gzip) and Date are added after this
-- filter. Age is not kept: nginx stores and replays the origin's value
-- unchanged, which would make a fresh copy look stale.
M.ORIGIN_HEADERS_KEPT = {
    ["content-type"] = true,
    ["content-length"] = true,
    ["content-range"] = true,
    ["content-encoding"] = true,
    ["content-language"] = true,
    ["content-disposition"] = true,
    ["etag"] = true,
    ["last-modified"] = true,
    ["accept-ranges"] = true,
}

-- Names of the headers to drop from `headers` (a get_headers() table).
-- `location` stays only on the node's own redirect.
function M.headers_to_drop(headers, own_redirect)
    local drop = {}
    for name in pairs(headers) do
        local n = name:lower()
        if not M.ORIGIN_HEADERS_KEPT[n] and not (own_redirect and n == "location") then
            drop[#drop + 1] = name
        end
    end
    return drop
end

-- Whether `host` is one of the fleet's own names (<id>.<suffix> under the
-- fleet wildcard), as opposed to a customer's custom domain.
function M.on_fleet_domain(host, store)
    local wildcard = store and store.doc.fleet_wildcard
    return type(host) == "string" and type(wildcard) == "string"
        and util.wildcard_of(host) == wildcard
end

function M.header_filter()
    -- Slice subrequests never reach the client: the main request is
    -- filtered once.
    if ngx.is_subrequest then
        return
    end
    local ctx = ngx.ctx
    -- The edge TTL the internal origin server set (stored with a cached
    -- response, so replayed on a HIT), read before the allowlist drops it.
    local stored_ttl = tonumber(ngx.header["X-Hippius-TTL"])
    for _, name in ipairs(M.headers_to_drop(ngx.resp.get_headers(0, true), ctx.redirect)) do
        ngx.header[name] = nil
    end
    -- Every response: no MIME sniffing a script-capable type out of a
    -- customer's bytes.
    ngx.header["X-Content-Type-Options"] = "nosniff"
    -- An empty object: S3 answers the first slice's ranged GET with 416
    -- and "Content-Range: bytes */0". Without a client Range, that is an
    -- empty 200.
    if ngx.status == 416 and ngx.var.http_range == nil
        and ngx.header["Content-Range"] == "bytes */0" then
        ngx.status = 200
        ngx.header["Content-Range"] = nil
        ngx.header["Content-Length"] = 0
        ngx.header["Content-Type"] = mime.fallback(ngx.var.uri, nil)
        local d = ctx.decision
        ngx.header["Cache-Control"] = M.client_cache_control(d,
            d and type(d.edge) == "number" and d.edge or nil)
        ctx.empty_body = true
        return
    end
    -- An origin redirect is not followed and its body (S3 XML naming the
    -- bucket and endpoint) is not passed on: like an error, a generic body,
    -- never cached. 304 is nginx's answer to a conditional request.
    local origin_redirect = ngx.status >= 300 and ngx.status < 400 and ngx.status ~= 304
        and not ctx.redirect
    if ngx.status >= 400 or origin_redirect then
        ctx.generic_body = true
        ngx.header["Content-Length"] = nil
        ngx.header["Content-Encoding"] = nil
        ngx.header["Content-Type"] = "text/plain"
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["Retry-After"] = ctx.retry_after
        return
    end
    if ctx.redirect then
        return
    end
    local t = mime.fallback(ngx.var.uri, ngx.header["Content-Type"])
    if t then
        ngx.header["Content-Type"] = t
    end
    if M.on_fleet_domain(ngx.var.host, docs.get("config")) then
        ngx.header["Content-Security-Policy"] = mime.csp_for(ngx.header["Content-Type"])
    end
    ngx.header["Cache-Control"] = M.client_cache_control(ctx.decision, stored_ttl)
end

function M.body_filter()
    local ctx = ngx.ctx
    if ctx.empty_body then
        ngx.arg[1] = nil
    elseif ctx.generic_body then
        if ngx.arg[2] then
            ngx.arg[1] = tostring(ngx.status) .. "\n"
        else
            ngx.arg[1] = nil
        end
    end
    -- Bandwidth ceiling: every body byte sent, the main request's and each
    -- slice subrequest's (the zone variable is shared with them; each has
    -- its own ctx). Added up per request and counted every ACCOUNT_BATCH
    -- bytes, at the second's end and at the last chunk (one shared-dict
    -- write per batch, not per buffer).
    local zone_id = ngx.var.hippius_zone
    if zone_id == nil or zone_id == "" then
        return
    end
    local now = ngx.time()
    local pending = ctx.limit_pending or 0
    if pending > 0 and ctx.limit_sec ~= now then
        limits.account(ngx.shared.hippius_limits, zone_id, pending, ctx.limit_sec)
        pending = 0
    end
    pending = pending + #(ngx.arg[1] or "")
    if pending >= ACCOUNT_BATCH or (ngx.arg[2] and pending > 0) then
        limits.account(ngx.shared.hippius_limits, zone_id, pending, now)
        pending = 0
    end
    ctx.limit_pending, ctx.limit_sec = pending, now
end

return M
