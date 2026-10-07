-- The agent's control documents: validation, storage, per-worker cache.
--
-- Each document is a full replacement. The raw JSON lives in the
-- `hippius_docs` shared dict (RAM only, shared by all workers, wiped by
-- an OpenResty restart, kept across a reload). Each worker decodes a
-- document once per version and keeps the decoded table, plus derived
-- indexes, until the version changes.
local cjson = require("cjson.safe")
local util = require("hippius_cdn.util")

local M = {}

M.NAMES = { config = true, secrets = true, certs = true, health = true, attestation = true }
-- The documents a working data plane needs; `health` answers 409 until
-- all three are present again (after an OpenResty restart).
M.REQUIRED = { "config", "secrets", "certs" }

local null = cjson.null
local cache = {}

local function is_map(t)
    return type(t) == "table"
end

local function opt_string(v)
    return v == nil or v == null or type(v) == "string"
end

local function bad(why)
    return nil, why
end

-- ── validators: return (derived table) or (nil, reason) ─────────────

local validators = {}

function validators.config(d)
    if type(d.revision) ~= "number" then return bad("revision") end
    if type(d.draining) ~= "boolean" then return bad("draining") end
    if type(d.fleet_wildcard) ~= "string" then return bad("fleet_wildcard") end
    if not is_map(d.zones) or not is_map(d.hostnames) or not is_map(d.purges) then
        return bad("sections")
    end
    local compression = {}
    for _, c in ipairs(type(d.compression) == "table" and d.compression or {}) do
        if c ~= "gzip" and c ~= "brotli" then return bad("compression") end
        compression[c] = true
    end
    for zid, z in pairs(d.zones) do
        if type(zid) ~= "string" or not is_map(z) then return bad("zone") end
        if z.state ~= "active" and z.state ~= "paused" and z.state ~= "suspended" then
            return bad("zone-state")
        end
        if type(z.serving) ~= "boolean" or not is_map(z.origin) then return bad("zone-origin") end
        if z.serving then
            -- A serving zone must carry an origin this data plane can use.
            if z.origin.type ~= "s3" or not util.valid_bucket(z.origin.bucket)
                or not util.valid_prefix(z.origin.prefix ~= null and z.origin.prefix or nil)
                or (z.origin.region ~= nil and not util.valid_region(z.origin.region)) then
                return bad("zone-origin")
            end
        end
    end
    -- Purge generations, keyed by the canonical (decoded) path form the
    -- router compares against $uri. Two encodings of one path keep the
    -- higher generation.
    local purges = {}
    local skipped = 0
    for zid, p in pairs(d.purges) do
        if type(zid) ~= "string" or not is_map(p) or type(p.zone_generation) ~= "number" then
            return bad("purge")
        end
        -- `prefixes` keys end in "/" (a directory); `paths` keys are one
        -- exact path each (absent: empty). A key that does not
        -- canonicalise ("/%2e%2e/x", "/a%00"), or a prefix without the
        -- trailing "/", can never match a request: it is skipped and
        -- counted rather than refusing the document, so one customer
        -- purge cannot freeze every node's config.
        local function collect(map, need_slash)
            local out = {}
            for key, gen in pairs(is_map(map) and map or {}) do
                if type(gen) ~= "number" then
                    return nil
                end
                local canon = util.canonical_feed_path(key)
                if not canon or (need_slash and canon:sub(-1) ~= "/") then
                    skipped = skipped + 1
                elseif not out[canon] or out[canon] < gen then
                    out[canon] = gen
                end
            end
            return out
        end
        local prefixes = collect(p.prefixes, false)
        local paths = collect(p.paths, false)
        if not prefixes or not paths then
            return bad("purge-generation")
        end
        -- A `prefixes` key without the trailing "/" is an exact path (the
        -- backend's form until it fills `paths`).
        for key, gen in pairs(prefixes) do
            if key:sub(-1) ~= "/" then
                prefixes[key] = nil
                if not paths[key] or paths[key] < gen then
                    paths[key] = gen
                end
            end
        end
        purges[zid] = { zone_generation = p.zone_generation, prefixes = prefixes, paths = paths }
    end
    local hostnames = {}
    for host, zid in pairs(d.hostnames) do
        local name = type(host) == "string" and host:gsub("^%*%.", "") or nil
        if not name or not util.valid_host(name) or type(zid) ~= "string" or not d.zones[zid] then
            return bad("hostname")
        end
        hostnames[host] = zid
    end
    local acme = {}
    for token, keyauth in pairs(is_map(d.acme_http01) and d.acme_http01 or {}) do
        if type(token) ~= "string" or not token:match("^[A-Za-z0-9_-]+$") or #token > 256
            or type(keyauth) ~= "string" or keyauth:sub(1, #token + 1) ~= token .. "."
            or not keyauth:match("^[A-Za-z0-9_.-]+$") or #keyauth > 512 then
            return bad("acme")
        end
        acme[token] = keyauth
    end
    -- Blocks: hostnames, exact paths and path prefixes, per zone or global.
    local blocks = { hosts = {}, exact = {}, prefixes = {} }
    for _, b in ipairs(type(d.blocks) == "table" and d.blocks or {}) do
        if not is_map(b) or type(b.value) ~= "string" or not opt_string(b.zone_id) then
            return bad("block")
        end
        local scope = (b.zone_id ~= nil and b.zone_id ~= null) and b.zone_id or "*"
        if b.kind == "hostname" then
            blocks.hosts[b.value] = true
        elseif b.kind == "path" or b.kind == "prefix" then
            local canon = util.canonical_feed_path(b.value)
            -- A prefix block is directory-aligned, like a purge prefix. A
            -- value that does not canonicalise matches no request path:
            -- skip it (logged) rather than refuse the whole document.
            if not canon or (b.kind == "prefix" and canon:sub(-1) ~= "/") then
                skipped = skipped + 1
            else
                local into = b.kind == "path" and blocks.exact or blocks.prefixes
                into[scope] = into[scope] or {}
                if b.kind == "path" then
                    into[scope][canon] = true
                else
                    into[scope][#into[scope] + 1] = canon
                end
            end
        else
            -- Unknown kind: skipped, like an unusable value.
            skipped = skipped + 1
        end
    end
    if skipped > 0 and ngx and ngx.log then
        ngx.log(ngx.WARN, "hippius-cdn: ", skipped, " purge keys or block values skipped (not a request path)")
    end
    return {
        doc = d,
        skipped = skipped,
        hostnames = hostnames,
        acme = acme,
        blocks = blocks,
        purges = purges,
        compression = compression,
    }
end

function validators.secrets(d)
    if not is_map(d.zones) then return bad("zones") end
    for zid, s in pairs(d.zones) do
        if type(zid) ~= "string" or not is_map(s) then return bad("zone") end
        for k, v in pairs(s) do
            if type(k) ~= "string" or type(v) ~= "string" then return bad("secret") end
        end
    end
    return { doc = d }
end

function validators.certs(d)
    if not is_map(d.certs) or not opt_string(d.default) then return bad("certs") end
    for host, c in pairs(d.certs) do
        if type(host) ~= "string" or not is_map(c) or type(c.chain_pem) ~= "string"
            or type(c.key_pem) ~= "string" then
            return bad("cert")
        end
    end
    local default = d.default ~= null and d.default or nil
    if default and not d.certs[default] then return bad("default") end
    -- `parsed` caches ngx.ssl cdata per hostname for this version.
    return { doc = d, default = default, parsed = {} }
end

function validators.health(d)
    if type(d.ready) ~= "boolean" or type(d.at) ~= "number" then return bad("health") end
    return { doc = d }
end

function validators.attestation(d)
    if type(d.format) ~= "string" or type(d.report_b64) ~= "string"
        or type(d.spki_sha256_hex) ~= "string" then
        return bad("attestation")
    end
    return { doc = d }
end

-- Validate a raw body. Returns (derived) or (nil, reason).
function M.validate(name, raw)
    if not M.NAMES[name] then return bad("unknown-document") end
    local d = cjson.decode(raw)
    if type(d) ~= "table" then return bad("json") end
    return validators[name](d)
end

local function dict()
    return ngx.shared.hippius_docs
end

-- Store a validated document. Returns true or (nil, reason).
function M.store(name, raw)
    local ok, err = dict():safe_set("doc:" .. name, raw)
    if not ok then
        return nil, "store-" .. tostring(err)
    end
    dict():incr("gen:" .. name, 1, 0)
    return true
end

function M.present(name)
    return dict():get("gen:" .. name) ~= nil
end

function M.all_required_present()
    for _, name in ipairs(M.REQUIRED) do
        if not M.present(name) then
            return false
        end
    end
    return true
end

-- The derived table of a document, decoded at most once per version
-- per worker. nil when the document is absent.
function M.get(name)
    local gen = dict():get("gen:" .. name)
    if gen == nil then
        cache[name] = nil
        return nil
    end
    local c = cache[name]
    if c and c.gen == gen then
        return c.value
    end
    local raw = dict():get("doc:" .. name)
    if raw == nil then
        return nil
    end
    local value = M.validate(name, raw)
    cache[name] = { gen = gen, value = value }
    return value
end

return M
