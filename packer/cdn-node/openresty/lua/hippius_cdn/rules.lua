-- A zone's cache rules (feed `settings.rules`), as the backend contract
-- states them (cdn-contracts.md in hippius-backend, C.4 "Rules", final
-- since #439; validated by cdn/rules.py):
--
--   match:   {path_prefix = "/static/"} | {glob = "*.jpg"} | {extensions = {"jpg"}}
--   actions: edge_ttl     seconds (0..1 year) or "origin" (honour the origin)
--            browser_ttl  seconds, or null (follow the edge TTL)
--            query_string "ignore" | "include" | {whitelist = {names}}
--            bypass       neither looked up nor stored
--            ignore_set_cookie  (a no-op: S3 origins never pass Set-Cookie)
--
-- The first rule whose match matches wins, whole: no other rule applies,
-- and its unset actions take the defaults.
--
-- The path matched is the decoded, normalised request path ($uri), as for
-- purges. Patterns arrive in the purge-path wire form (percent-encoded)
-- and are decoded once:
--   path_prefix  the path starts with it (case-sensitive);
--   glob         `*` any run of characters within one segment (never "/"),
--                `?` one character other than "/", `**` any run across
--                segments ("/" included), every other character literal;
--                without "/" it is matched against the last segment, one
--                starting with "/" against the whole path; case-sensitive;
--   extensions   the last segment contains a "." and what follows its last
--                "." equals one of them, case-insensitively.
--
-- A rule this node cannot use is dropped (and counted), never fatal: the
-- backend validates rules, so this only guards a feed it did not.
local bit = require("bit")
local util = require("hippius_cdn.util")

local band, bor, lshift, rshift = bit.band, bit.bor, bit.lshift, bit.rshift
local byte, sub, find = string.byte, string.sub, string.find

local M = {}

M.MAX_TTL = 365 * 86400
local MAX_RULES = 50
-- A zone's `glob` patterns total at most this many bytes, their wire form
-- as stored, summed over its rules (contract C.4; the backend validates the
-- same cap). It bounds the per-request matching work (path length x pattern
-- words). Over it, every glob rule of the zone is ignored; its other rules
-- still apply.
M.GLOB_CAP = 2048

local null = (require("cjson.safe")).null
local SLASH = 47

local function ttl(v, allow_origin)
    if allow_origin and v == "origin" then
        return v
    end
    if type(v) == "number" and v >= 0 and v <= M.MAX_TTL and v % 1 == 0 then
        return v
    end
    return nil
end

-- The wire form: printable ASCII, every "%" a two-hex-digit escape.
local function wire_form(s, max)
    if type(s) ~= "string" or #s < 1 or #s > max or s:find("[^\33-\126]") then
        return false
    end
    local rest = s:gsub("%%%x%x", "")
    return not rest:find("%", 1, true)
end

-- ── glob: bit-parallel (Shift-And with wildcards) ──────────────────────
-- Each non-star character of the pattern is a position; bit i of the state
-- set means "positions 0..i matched, ending here". A star after position i
-- keeps bit i set across bytes: any byte for `**`, any but "/" for `*`. One
-- pass over the target, ceil(m/32) words per byte: the cost depends on the
-- target and pattern lengths only, whatever either contains.

-- Compile a decoded glob, or nil when unusable.
function M.compile_glob(g)
    if type(g) ~= "string" or g == "" or g:find("[%z\1-\31\127\\]") or g:find("***", 1, true) then
        return nil
    end
    local basename = not g:find("/", 1, true)
    if not basename and byte(g, 1) ~= SLASH then
        return nil -- a "/" anywhere but at the start
    end
    local positions = {}      -- byte value, or false for `?`
    local after = {}          -- [i] = "*" | "**": the star following position i
    local lead = nil          -- the star before the first position
    local i = 1
    while i <= #g do
        local c = byte(g, i)
        if c == 42 then -- "*"
            local kind = (byte(g, i + 1) == 42) and "**" or "*"
            if #positions == 0 then
                lead = kind
            else
                after[#positions] = kind
            end
            i = i + #kind
        else
            if c == 63 then -- "?"
                positions[#positions + 1] = false
            else
                positions[#positions + 1] = c
            end
            i = i + 1
        end
    end
    local m = #positions
    if m == 0 then
        return { all = lead, basename = basename }
    end
    local words = math.ceil(m / 32)
    local any, star, star_double, by = {}, {}, {}, {}
    for w = 1, words do
        any[w], star[w], star_double[w] = 0, 0, 0
    end
    for k = 1, m do
        local w, b = rshift(k - 1, 5) + 1, lshift(1, band(k - 1, 31))
        if positions[k] == false then
            any[w] = bor(any[w], b)
        else
            local c = positions[k]
            by[c] = by[c] or {}
            by[c][w] = bor(by[c][w] or 0, b)
        end
        if after[k] then
            star[w] = bor(star[w], b)
            if after[k] == "**" then
                star_double[w] = bor(star_double[w], b)
            end
        end
    end
    -- Per byte: the positions it can advance. `?` takes any byte but "/".
    local masks = {}
    for c, mk in pairs(by) do
        local t = {}
        for w = 1, words do
            t[w] = c == SLASH and (mk[w] or 0) or bor(any[w], mk[w] or 0)
        end
        masks[c] = t
    end
    if not masks[SLASH] then
        local t = {}
        for w = 1, words do t[w] = 0 end
        masks[SLASH] = t
    end
    return {
        basename = basename, lead = lead, words = words, any = any, masks = masks,
        star = star, star_double = star_double,
        last_w = rshift(m - 1, 5) + 1, last_b = lshift(1, band(m - 1, 31)),
    }
end

local function last_segment(path)
    for i = #path, 1, -1 do
        if byte(path, i) == SLASH then
            return sub(path, i + 1)
        end
    end
    return path
end

function M.glob_match(gl, path)
    local target = gl.basename and last_segment(path) or path
    if gl.all then
        return gl.all == "**" or not find(target, "/", 1, true)
    end
    local words, any, masks = gl.words, gl.any, gl.masks
    local d, nd = {}, {}
    for w = 1, words do d[w] = 0 end
    -- The start state: before the first byte, then for as long as a leading
    -- star can absorb the bytes read.
    local start = true
    for i = 1, #target do
        local c = byte(target, i)
        local mk = masks[c] or any
        local keep = (c == SLASH) and gl.star_double or gl.star
        local carry = start and 1 or 0
        local alive = 0
        for w = 1, words do
            local dw = d[w]
            local v = bor(band(bor(lshift(dw, 1), carry), mk[w]), band(dw, keep[w]))
            carry = band(rshift(dw, 31), 1)
            nd[w] = v
            alive = bor(alive, v)
        end
        d, nd = nd, d
        -- A leading `*` dies at the first "/", a leading `**` never.
        start = start and (gl.lead == "**" or (gl.lead == "*" and c ~= SLASH))
        if alive == 0 and not start then
            return false
        end
    end
    return band(d[gl.last_w], gl.last_b) ~= 0
end

-- ── compile ────────────────────────────────────────────────────────────

local function compile_match(m)
    if type(m) ~= "table" then
        return nil
    end
    local n = 0
    for _ in pairs(m) do n = n + 1 end
    if n ~= 1 then
        return nil
    end
    if m.path_prefix ~= nil then
        local p = m.path_prefix
        if not wire_form(p, 512) or byte(p, 1) ~= SLASH then
            return nil
        end
        -- Decoded (and slash-merged) as nginx builds $uri, as for purges.
        local canon = util.canonical_feed_path(p)
        return canon and { kind = "prefix", prefix = canon } or nil
    elseif m.glob ~= nil then
        if not wire_form(m.glob, 256) then
            return nil
        end
        local decoded = util.percent_decode(m.glob)
        local gl = M.compile_glob(decoded)
        return gl and { kind = "glob", glob = gl } or nil
    elseif m.extensions ~= nil then
        local list = m.extensions
        if type(list) ~= "table" or #list < 1 or #list > 50 then
            return nil
        end
        local set = {}
        for _, e in ipairs(list) do
            if type(e) ~= "string" then
                return nil
            end
            e = e:gsub("^%.", ""):lower()
            if e == "" or #e > 16 or e:find("[^%w]") then
                return nil
            end
            set[e] = true
        end
        return { kind = "ext", set = set }
    end
    return nil
end

local function compile_actions(a)
    if type(a) ~= "table" then
        return nil
    end
    local out, n = {}, 0
    for k, v in pairs(a) do
        n = n + 1
        if k == "edge_ttl" then
            out.edge = ttl(v, true)
            if out.edge == nil then return nil end
        elseif k == "browser_ttl" then
            if v ~= null then
                out.browser = ttl(v, false)
                if out.browser == nil then return nil end
            end
        elseif k == "query_string" then
            if v == "ignore" or v == "include" then
                out.qs = v
            elseif type(v) == "table" and type(v.whitelist) == "table" and #v.whitelist >= 1
                and #v.whitelist <= 50 then
                local set = {}
                for _, name in ipairs(v.whitelist) do
                    if type(name) ~= "string" or name == "" or #name > 64 then
                        return nil
                    end
                    set[name] = true
                end
                out.qs = { whitelist = set }
            else
                return nil
            end
        elseif k == "bypass" then
            if type(v) ~= "boolean" then return nil end
            out.bypass = v
        elseif k == "ignore_set_cookie" then
            if type(v) ~= "boolean" then return nil end
        else
            -- An action this node does not know: the rule is not applied
            -- rather than applied in part.
            return nil
        end
    end
    if n == 0 then
        return nil
    end
    return out
end

-- Compile a zone's `settings.rules`: the usable rules in order, and how
-- many were dropped.
-- The wire bytes of the `glob` patterns among `raw`'s first MAX_RULES rules.
local function glob_wire_bytes(raw)
    local n = 0
    for i, r in ipairs(raw) do
        if i > MAX_RULES then
            break
        end
        local g = type(r) == "table" and type(r.match) == "table" and r.match.glob
        if type(g) == "string" then
            n = n + #g
        end
    end
    return n
end

function M.compile(raw)
    local out, dropped = {}, 0
    if raw == nil or raw == null then
        return out, 0, false
    end
    if type(raw) ~= "table" then
        return out, 1, false
    end
    local over_cap = glob_wire_bytes(raw) > M.GLOB_CAP
    for i, r in ipairs(raw) do
        local m = i <= MAX_RULES and type(r) == "table" and compile_match(r.match) or nil
        local a = m and compile_actions(r.actions)
        if m and m.kind == "glob" and over_cap then
            a = nil
        end
        if m and a then
            m.actions = a
            out[#out + 1] = m
        else
            dropped = dropped + 1
        end
    end
    return out, dropped, over_cap
end

-- ── evaluation ─────────────────────────────────────────────────────────

-- The lowercased text after the last "." of the last segment, or nil.
function M.last_extension(path)
    local name = last_segment(path)
    for i = #name, 1, -1 do
        if byte(name, i) == 46 then
            return sub(name, i + 1):lower()
        end
    end
    return nil
end

-- The first rule of `compiled` matching the decoded `path`, or nil.
function M.match(compiled, path)
    if not compiled or #compiled == 0 then
        return nil
    end
    local ext = nil
    for _, r in ipairs(compiled) do
        if r.kind == "prefix" then
            if sub(path, 1, #r.prefix) == r.prefix then
                return r
            end
        elseif r.kind == "ext" then
            ext = ext or M.last_extension(path) or false
            if ext and r.set[ext] then
                return r
            end
        elseif M.glob_match(r.glob, path) then
            return r
        end
    end
    return nil
end

-- What a request does under `rule` (nil: no rule matched):
--   edge         "default" | "origin" | seconds (the internal origin
--                server turns it into X-Accel-Expires)
--   bypass       neither looked up nor stored
--   skip_lookup  the cache is not read (bypass, or edge_ttl 0: every
--                request goes to the origin; a 404 is still stored)
--   browser      client max-age, or nil to follow the edge TTL
--   qs           the query-string mode for the cache key
function M.decide(rule)
    local a = rule and rule.actions or {}
    local d = {
        edge = a.edge ~= nil and a.edge or "default",
        bypass = a.bypass == true,
        browser = a.browser,
        qs = a.qs or "ignore",
    }
    d.skip_lookup = d.bypass or d.edge == 0
    return d
end

-- The value of the internal X-Hippius-Edge-TTL request header.
function M.edge_header(d)
    if d.skip_lookup then
        return "0"
    end
    return tostring(d.edge)
end

-- The query part of the cache key: the raw query split on "&", each part
-- at its first "=" (none: an empty value), kept as sent (never decoded),
-- empty and duplicate parameters included; the kept ones sorted bytewise
-- by name then value, joined back with "&" and "=".
function M.query_key(qs, args)
    if qs == nil or qs == "ignore" or type(args) ~= "string" then
        return ""
    end
    local keep, i = {}, 1
    while true do
        local amp = find(args, "&", i, true)
        local part = sub(args, i, amp and amp - 1 or #args)
        local at = find(part, "=", 1, true)
        local name = at and sub(part, 1, at - 1) or part
        local value = at and sub(part, at + 1) or ""
        if qs == "include" or (type(qs) == "table" and qs.whitelist[name]) then
            keep[#keep + 1] = { name, value }
        end
        if not amp then
            break
        end
        i = amp + 1
    end
    if #keep == 0 then
        return ""
    end
    table.sort(keep, function(a, b)
        if a[1] ~= b[1] then
            return a[1] < b[1]
        end
        return a[2] < b[2]
    end)
    local out = {}
    for k, p in ipairs(keep) do
        out[k] = p[1] .. "=" .. p[2]
    end
    return table.concat(out, "&")
end

-- The S3 gateway's blanket Cache-Control: exactly the two directives
-- `private` and `no-store`, in either order, any case and spacing, and
-- nothing else. It counts as no header under edge_ttl "origin" (contract).
function M.is_gateway_blanket(cache_control)
    if type(cache_control) ~= "string" then
        return false
    end
    local seen, n = {}, 0
    for part in (cache_control:lower() .. ","):gmatch("([^,]*),") do
        local d = part:match("^%s*(.-)%s*$")
        if d ~= "private" and d ~= "no-store" then
            return false
        end
        if not seen[d] then
            seen[d] = true
            n = n + 1
        end
    end
    return n == 2
end

-- Seconds the edge keeps a response under edge_ttl "origin", from the
-- origin's Cache-Control and Expires (`now`: Unix time). 0 = do not
-- cache; nil = the origin said nothing usable (the default applies). The
-- S3 gateway's blanket "private, no-store" counts as no header (contract).
function M.origin_ttl(cache_control, expires, now)
    if type(cache_control) == "string" and cache_control ~= "" then
        local cc = cache_control:lower()
        if M.is_gateway_blanket(cc) then
            cc = ""
        end
        for _, word in ipairs({ "no%-store", "no%-cache", "private" }) do
            if cc:find("%f[%w-]" .. word .. "%f[^%w-]") then
                return 0
            end
        end
        local s = cc:match("s%-maxage%s*=%s*(%d+)") or cc:match("%f[%w-]max%-age%s*=%s*(%d+)")
        if s then
            local n = tonumber(s)
            return n and math.min(n, M.MAX_TTL) or nil
        end
    end
    if type(expires) == "string" and expires ~= "" and ngx and ngx.parse_http_time then
        local at = ngx.parse_http_time(expires)
        if not at then
            return 0 -- an invalid Expires means already expired (RFC 9111)
        end
        return math.max(0, math.min(at - now, M.MAX_TTL))
    end
    return nil
end

return M
