-- A zone serving a static site or a single-page app (feed `settings`,
-- contract C.4 "Zone settings", feed schema 3; validated by cdn/site.py in
-- the backend, and by the agent's `site` module):
--
--   index_document        null (no index) or one file name, 1-128 of
--                         [A-Za-z0-9._-], never "." and no "..": "/" and
--                         every path ending in "/" fetch
--                         <prefix><path><index_document>
--   spa_fallback          bool (default false, needs an index_document): an
--                         origin 404 on GET/HEAD, on a path under none of
--                         the excludes, serves the index document with 200
--   spa_fallback_exclude  0 to 16 directory prefixes (default {"/assets/"}),
--                         each starting and ending with "/", at most 256
--                         bytes, in the purge-path wire form
--
-- A feed without these keys (an older backend) is today's behaviour: no
-- index, no fallback. An unusable value turns its feature off (logged by
-- the caller), never a refused document: an unusable index_document turns
-- off both, an unusable exclude list turns off the fallback (it must never
-- answer 200 where the customer asked for a 404).
local util = require("hippius_cdn.util")

local M = {}

local cjson = require("cjson.safe")
local null = cjson.null

M.INDEX_MAX = 128
M.MAX_EXCLUDES = 16
M.EXCLUDE_MAX_BYTES = 256
M.DEFAULT_EXCLUDES = { "/assets/" }

-- What a zone without these keys gets.
M.OFF = { index = nil, fallback = false, exclude = {} }

function M.valid_index(v)
    return type(v) == "string" and #v >= 1 and #v <= M.INDEX_MAX
        and v:find("^[A-Za-z0-9._-]+$") ~= nil and v ~= "." and not v:find("..", 1, true)
end

-- The canonical (decoded, slash-merged) form of one exclude prefix, or nil.
local function exclude_prefix(v)
    if type(v) ~= "string" or #v > M.EXCLUDE_MAX_BYTES or v:find("[^\33-\126]")
        or v:find("[?#]") or v:sub(1, 1) ~= "/" or v:sub(-1) ~= "/" then
        return nil
    end
    -- Decoded and slash-merged like $uri (still ending in "/"); nil for a
    -- "." / ".." segment, a control byte or a backslash.
    return util.canonical_feed_path(v)
end

-- A JSON array (docs.lua decodes with cjson.array_mt): `{}` is an object,
-- refused like the agent refuses it.
local function is_array(t)
    return getmetatable(t) == cjson.array_mt
end

-- The excludes as canonical prefixes; the default when the key is absent or
-- null; nil when unusable.
function M.excludes(v)
    if v == nil or v == null then
        return M.DEFAULT_EXCLUDES
    end
    if type(v) ~= "table" or not is_array(v) or #v > M.MAX_EXCLUDES then
        return nil
    end
    local out = {}
    for i, e in ipairs(v) do
        local canon = exclude_prefix(e)
        if not canon then
            return nil
        end
        out[i] = canon
    end
    return out
end

-- A zone's site settings `{index, fallback, exclude}` from its `settings`
-- object, and the reasons a value was unusable (empty when none was).
function M.of(settings_doc)
    if type(settings_doc) ~= "table" then
        return M.OFF, {}
    end
    local problems = {}
    local index = settings_doc.index_document
    if index == null then
        index = nil
    end
    if index ~= nil and not M.valid_index(index) then
        problems[#problems + 1] = "index_document"
        index = nil
    end
    local fallback = settings_doc.spa_fallback
    if fallback == nil or fallback == null then
        fallback = false
    elseif type(fallback) ~= "boolean" then
        problems[#problems + 1] = "spa_fallback"
        fallback = false
    end
    local exclude = M.excludes(settings_doc.spa_fallback_exclude)
    if exclude == nil then
        problems[#problems + 1] = "spa_fallback_exclude"
        fallback, exclude = false, {}
    end
    if fallback and not index then
        problems[#problems + 1] = "spa_fallback without index_document"
        fallback = false
    end
    return { index = index, fallback = fallback, exclude = exclude }, problems
end

-- The object path a request path fetches: <path><index> for a directory
-- path ("/", "/a/") when the zone has an index, else the path itself. The
-- index is one file name (no "/", never "." or ".."), so the result stays a
-- valid request path under the same directory.
function M.object_path(site, path)
    if site and site.index and path:sub(-1) == "/" then
        return path .. site.index
    end
    return path
end

-- The path of the zone's index document, the object a fallback serves (the
-- same cache entry as a direct GET of it).
function M.fallback_path(site)
    return "/" .. site.index
end

-- Whether an origin 404 for `path` (the decoded request path, which
-- fetched `object_path`) may be answered with the index document: the zone
-- falls back, the path is under no exclude, and the object is not the index
-- document itself (that would only fetch the same missing object again).
function M.falls_back(site, path, object_path)
    if not site or not site.fallback or not site.index then
        return false
    end
    if (object_path or path) == M.fallback_path(site) then
        return false
    end
    for _, prefix in ipairs(site.exclude) do
        if path:sub(1, #prefix) == prefix then
            return false
        end
    end
    return true
end

return M
