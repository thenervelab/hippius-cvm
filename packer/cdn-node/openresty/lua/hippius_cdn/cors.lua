-- A zone's CORS policy (feed `settings.cors`, contract C.4 "Zone
-- settings"; the agent's `cors` module checks the same rules):
--
--   allow_origins      1 to 32: ["*"], or origins "scheme://host[:port]"
--                      (http or https, lower case, no path, no default
--                      port), or "scheme://*.suffix[:port]": exactly one
--                      label in place of "*", the suffix at least two labels
--   allow_methods      a non-empty subset of {"GET", "HEAD"} (default both):
--                      the node serves nothing else, and answers OPTIONS
--   allow_headers      up to 32 header names, or ["*"] (default none)
--   expose_headers     up to 32 header names, or ["*"] (default none)
--   max_age            seconds, 0 to 86400 (absent: no Access-Control-Max-Age)
--   allow_credentials  bool (default false); never with a "*"
--
-- The headers are computed for each response from the zone's policy and
-- the request's Origin, after the origin's own headers were dropped
-- (router.ORIGIN_HEADERS_KEPT): nothing here is ever stored in the cache,
-- whose key never depends on Origin.
--
-- An unusable policy is ignored whole (logged by the caller): the zone
-- then serves exactly as without one. Unknown keys are ignored.
local cjson = require("cjson.safe")

local M = {}

local null = cjson.null

M.MAX_ORIGINS = 32
M.MAX_HEADERS = 32
M.MAX_HEADER_LEN = 64
M.MAX_AGE = 86400
local METHODS = { GET = true, HEAD = true }

local function is_array(t)
    return type(t) == "table" and getmetatable(t) == cjson.array_mt
end

-- A host as a browser serialises it in Origin: lower-case LDH labels
-- (one label allowed: localhost).
local function valid_host(h, min_labels)
    if type(h) ~= "string" or #h == 0 or #h > 253 then
        return false
    end
    local labels = 0
    for label in (h .. "."):gmatch("([^.]*)%.") do
        if #label == 0 or #label > 63 or not label:match("^[a-z0-9-]+$")
            or label:sub(1, 1) == "-" or label:sub(-1) == "-" then
            return false
        end
        labels = labels + 1
    end
    return labels >= min_labels
end

-- {scheme, host, port} of "scheme://host[:port]", or nil.
local function split_origin(o)
    if type(o) ~= "string" or #o > 300 then
        return nil
    end
    local scheme, rest = o:match("^(https?)://(.+)$")
    if not scheme then
        return nil
    end
    local host, port = rest:match("^([^:/]+):(%d+)$")
    if not host then
        host, port = rest, nil
        if host:find("[:/]") then
            return nil
        end
    end
    if port then
        local n = tonumber(port)
        if port:sub(1, 1) == "0" or n < 1 or n > 65535
            or (scheme == "https" and n == 443) or (scheme == "http" and n == 80) then
            return nil
        end
    end
    return scheme, host, port or ""
end

-- One allow_origins entry: {exact = origin} or {scheme, suffix, port}.
local function compile_origin(o)
    local scheme, host, port = split_origin(o)
    if not scheme then
        return nil
    end
    if host:sub(1, 2) == "*." then
        local suffix = host:sub(3)
        if not valid_host(suffix, 2) then
            return nil
        end
        return { scheme = scheme, suffix = "." .. suffix, port = port }
    end
    if not valid_host(host, 1) then
        return nil
    end
    return { exact = o }
end

-- Header names (lower case, deduplicated) and their joined form, or nil.
-- `star`: whether ["*"] is accepted.
local function header_list(v, star)
    if v == nil or v == null then
        return {}, ""
    end
    if not is_array(v) or #v > M.MAX_HEADERS then
        return nil
    end
    if star and #v == 1 and v[1] == "*" then
        return { ["*"] = true }, "*"
    end
    local set, names = {}, {}
    for _, h in ipairs(v) do
        if type(h) ~= "string" or #h == 0 or #h > M.MAX_HEADER_LEN
            or not h:match("^[A-Za-z0-9!#$%%&'*+.^_`|~-]+$") or h == "*" then
            return nil
        end
        local lower = h:lower()
        if not set[lower] then
            set[lower] = true
            names[#names + 1] = lower
        end
    end
    return set, table.concat(names, ", ")
end

-- The compiled policy of a zone's `settings`, or nil; and the reason a
-- present policy was unusable (nil when absent or usable).
function M.of(settings_doc)
    local c = type(settings_doc) == "table" and settings_doc.cors or nil
    if c == nil or c == null then
        return nil
    end
    if type(c) ~= "table" or is_array(c) then
        return nil, "cors"
    end
    local credentials = c.allow_credentials
    if credentials == nil or credentials == null then
        credentials = false
    elseif type(credentials) ~= "boolean" then
        return nil, "allow_credentials"
    end
    local origins = c.allow_origins
    if not is_array(origins) or #origins < 1 or #origins > M.MAX_ORIGINS then
        return nil, "allow_origins"
    end
    local out = { exact = {}, wild = {}, credentials = credentials }
    if #origins == 1 and origins[1] == "*" then
        if credentials then
            return nil, "allow_origins * with allow_credentials"
        end
        out.any = true
    else
        for _, o in ipairs(origins) do
            local compiled = compile_origin(o)
            if not compiled then
                return nil, "allow_origins"
            end
            if compiled.exact then
                out.exact[compiled.exact] = true
            else
                out.wild[#out.wild + 1] = compiled
            end
        end
    end
    local methods = c.allow_methods
    if methods == nil or methods == null then
        out.methods = { GET = true, HEAD = true }
        out.methods_str = "GET, HEAD"
    else
        if not is_array(methods) or #methods < 1 or #methods > 2 then
            return nil, "allow_methods"
        end
        out.methods, out.methods_str = {}, {}
        for _, m in ipairs(methods) do
            if not METHODS[m] then
                return nil, "allow_methods"
            end
            if not out.methods[m] then
                out.methods[m] = true
                out.methods_str[#out.methods_str + 1] = m
            end
        end
        out.methods_str = table.concat(out.methods_str, ", ")
    end
    local headers, headers_str = header_list(c.allow_headers, not credentials)
    if not headers then
        return nil, "allow_headers"
    end
    out.headers, out.headers_str = headers, headers_str
    local expose, expose_str = header_list(c.expose_headers, not credentials)
    if not expose then
        return nil, "expose_headers"
    end
    out.expose_str = expose_str
    local max_age = c.max_age
    if max_age ~= nil and max_age ~= null then
        if type(max_age) ~= "number" or max_age < 0 or max_age > M.MAX_AGE or max_age % 1 ~= 0 then
            return nil, "max_age"
        end
        -- "%d": JSON -0 is a valid 0, never sent as "-0".
        out.max_age = string.format("%d", max_age)
    end
    return out
end

-- Whether `origin` (the request's Origin header) is allowed by `c`.
function M.allowed(c, origin)
    if type(origin) ~= "string" then
        return false
    end
    if c.any then
        return true
    end
    if c.exact[origin] then
        return true
    end
    if #c.wild == 0 then
        return false
    end
    local scheme, host, port = split_origin(origin)
    if not scheme then
        return false
    end
    for _, w in ipairs(c.wild) do
        if w.scheme == scheme and w.port == port and #host > #w.suffix
            and host:sub(-#w.suffix) == w.suffix then
            local label = host:sub(1, #host - #w.suffix)
            if not label:find(".", 1, true) and valid_host(label, 1) then
                return true
            end
        end
    end
    return false
end

-- The CORS headers of an ordinary response (a name -> value table; empty
-- when none). With ["*"] and no credentials every response carries
-- `Access-Control-Allow-Origin: *`, whatever the request; with a list,
-- every response carries `Vary: Origin` (a browser or downstream cache
-- must not hand a response made for one origin to another), and the
-- allowed origin is echoed.
function M.response_headers(c, origin)
    if c.any then
        local h = { ["Access-Control-Allow-Origin"] = "*" }
        if c.expose_str ~= "" then
            h["Access-Control-Expose-Headers"] = c.expose_str
        end
        return h
    end
    local h = { Vary = "Origin" }
    if M.allowed(c, origin) then
        h["Access-Control-Allow-Origin"] = origin
        if c.credentials then
            h["Access-Control-Allow-Credentials"] = "true"
        end
        if c.expose_str ~= "" then
            h["Access-Control-Expose-Headers"] = c.expose_str
        end
    end
    return h
end

-- Whether every header `requested` (Access-Control-Request-Headers, a
-- comma-separated list) is allowed.
local function headers_allowed(c, requested)
    if requested == nil or requested == "" or c.headers["*"] then
        return true
    end
    for name in requested:gmatch("[^,]+") do
        name = name:match("^%s*(.-)%s*$"):lower()
        if name ~= "" and not c.headers[name] then
            return false
        end
    end
    return true
end

-- The headers of a preflight answer (always a 204): the allow headers when
-- the origin, the method and every requested header are allowed, else
-- only Vary (the browser then refuses the actual request).
function M.preflight_headers(c, origin, method, requested)
    local h = c.any and {} or { Vary = "Origin" }
    if not (M.allowed(c, origin) and c.methods[method] and headers_allowed(c, requested)) then
        return h
    end
    h["Access-Control-Allow-Origin"] = c.any and "*" or origin
    h["Access-Control-Allow-Methods"] = c.methods_str
    if c.headers["*"] then
        -- "*" in Allow-Headers is a wildcard only without credentials (it
        -- never comes with them); echo what was asked, which covers both,
        -- when it is a plain list of header names (client bytes never
        -- reach a response header otherwise).
        if requested and #requested <= 2048
            and requested:match("^[A-Za-z0-9!#$%%&'*+.^_`|~, -]+$") then
            h["Access-Control-Allow-Headers"] = requested
        end
    elseif c.headers_str ~= "" then
        h["Access-Control-Allow-Headers"] = c.headers_str
    end
    if c.max_age then
        h["Access-Control-Max-Age"] = c.max_age
    end
    if c.credentials then
        h["Access-Control-Allow-Credentials"] = "true"
    end
    return h
end

return M
