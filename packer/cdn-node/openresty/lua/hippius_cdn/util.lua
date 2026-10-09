-- Pure helpers (no ngx.* side effects), unit-tested in tests/unit.
local M = {}

local byte, char, format, sub, find = string.byte, string.char, string.format, string.sub, string.find

-- A request Host: lower-case LDH labels, at least two, total <= 253.
-- nginx already lower-cases $host and strips the port; this refuses
-- anything else (IP literals included: zones are named hosts).
function M.valid_host(h)
    if type(h) ~= "string" or #h == 0 or #h > 253 then
        return false
    end
    local labels = 0
    for label in (h .. "."):gmatch("([^.]*)%.") do
        if #label == 0 or #label > 63 then
            return false
        end
        if not label:match("^[a-z0-9-]+$") or sub(label, 1, 1) == "-" or sub(label, -1) == "-" then
            return false
        end
        labels = labels + 1
    end
    return labels >= 2 and not h:match("^[0-9.]+$")
end

-- The decoded, normalised request path ($uri) must not carry anything
-- that could change the object key or escape the bucket once
-- re-encoded: control bytes, backslash, or a "." / ".." segment.
function M.valid_path(p)
    if type(p) ~= "string" or sub(p, 1, 1) ~= "/" or #p > 4096 then
        return false
    end
    if find(p, "[%z\1-\31\127\\]") then
        return false
    end
    for seg in (p .. "/"):gmatch("([^/]*)/") do
        if seg == "." or seg == ".." then
            return false
        end
    end
    return true
end

-- Percent-decode (no "+" → space: these are paths, not form fields).
function M.percent_decode(s)
    return (s:gsub("%%(%x%x)", function(h)
        return char(tonumber(h, 16))
    end))
end

-- The canonical form of a path from the feed (block values, purge
-- prefixes): the backend sends it percent-encoded; requests are matched
-- on nginx's decoded, slash-merged $uri, so decode and merge the same
-- way. nil when the result is not a valid request path.
function M.canonical_feed_path(p)
    if type(p) ~= "string" then
        return nil
    end
    local d = M.percent_decode(p):gsub("//+", "/")
    if not M.valid_path(d) then
        return nil
    end
    return d
end

-- RFC 3986 percent-encoding of everything but unreserved, keeping "/".
-- This is SigV4's canonical URI encoding for S3 (single pass).
function M.encode_path(p)
    return (p:gsub("[^A-Za-z0-9%-%._~/]", function(c)
        return format("%%%02X", byte(c))
    end))
end

-- S3 bucket naming (mirrors the agent's S3OnlyPolicy).
function M.valid_bucket(b)
    return type(b) == "string" and #b >= 3 and #b <= 63
        and b:match("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") ~= nil
end

-- Object-key prefix (mirrors the agent): relative, ends with "/" (so
-- "site" cannot reach "site-private/..."), printable, none of ? # % \,
-- no "." / ".." segment.
function M.valid_prefix(p)
    if p == nil or p == "" then
        return true
    end
    if type(p) ~= "string" or #p > 1024 or sub(p, 1, 1) == "/" or sub(p, -1) ~= "/" then
        return false
    end
    if find(p, "[^\33-\126]") or find(p, "[?#%%\\]") then
        return false
    end
    for seg in (p .. "/"):gmatch("([^/]*)/") do
        if seg == "." or seg == ".." then
            return false
        end
    end
    return true
end

function M.valid_region(r)
    return type(r) == "string" and #r > 0 and #r <= 32 and r:match("^[A-Za-z0-9-]+$") ~= nil
end

-- Every directory prefix that covers `path`: "/", "/a/", "/a/b/". Exact
-- paths are a separate purge map (`paths`).
function M.purge_prefixes(path)
    local out = { "/" }
    local pos = 2
    while true do
        local slash = find(path, "/", pos, true)
        if not slash then
            break
        end
        out[#out + 1] = sub(path, 1, slash)
        pos = slash + 1
    end
    return out
end

-- The cache key material (hashed by the caller): zone, zone generation,
-- the generation of every covering directory prefix, the exact-path
-- generation, and the path. Hostnames of one zone share objects; the
-- query string never reaches the origin, so it is not part of the key.
-- `query` (optional) is the cache rule's query-string part
-- (rules.query_key): empty for the default, so default keys never change.
function M.cache_key_material(zone_id, purge, path, query)
    local zgen = 0
    local prefixes, paths = {}, {}
    if purge then
        zgen = tonumber(purge.zone_generation) or 0
        prefixes = purge.prefixes or {}
        paths = purge.paths or {}
    end
    local gens = {}
    for i, p in ipairs(M.purge_prefixes(path)) do
        gens[i] = tostring(tonumber(prefixes[p]) or 0)
    end
    local parts = {
        "v2", zone_id, tostring(zgen), table.concat(gens, ","), tostring(tonumber(paths[path]) or 0), path,
    }
    if query and query ~= "" then
        parts[#parts + 1] = "q=" .. query
    end
    return table.concat(parts, "\0")
end

-- The wildcard name that covers `host` ("*.b.c" for "a.b.c").
function M.wildcard_of(host)
    local dot = find(host, ".", 1, true)
    if not dot then
        return nil
    end
    return "*" .. sub(host, dot)
end

-- `$upstream_bytes_received` may list several upstream attempts.
function M.sum_list(s)
    local total = 0
    if type(s) ~= "string" then
        return 0
    end
    for n in s:gmatch("%d+") do
        total = total + tonumber(n)
    end
    return total
end

M.char = char
return M
