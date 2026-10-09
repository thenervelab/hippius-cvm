-- Client country for metering: ISO 3166 alpha-2 from a MaxMind DB
-- (DB-IP Lite Country, baked into the image), "XX" when unknown.
--
-- A minimal reader of the MaxMind DB format (binary search tree + data
-- section), country only, over the file's bytes through the LuaJIT FFI.
-- The file is loaded once in init_by_lua (the master), so the workers
-- share it copy-on-write. Nothing here can fail a request: a missing or
-- malformed database, an unparsable address, a private address or an
-- address without an entry all give "XX".
local ffi = require("ffi")
local bit = require("bit")

local band, bor, lshift, rshift = bit.band, bit.bor, bit.lshift, bit.rshift
local byte, sub, find = string.byte, string.sub, string.find

local M = {}

M.UNKNOWN = "XX"

local MARKER = "\171\205\239MaxMind.com"
-- The metadata sits in the last 128 KiB of the file.
local METADATA_MAX = 128 * 1024

local db -- the loaded database, or nil

-- ── data section decoding ──────────────────────────────────────────

local T_POINTER, T_STRING, T_DOUBLE, T_BYTES, T_U16, T_U32, T_MAP =
    1, 2, 3, 4, 5, 6, 7
local T_I32, T_U64, T_U128, T_ARRAY, T_BOOL, T_FLOAT = 8, 9, 10, 11, 14, 15

local function bounds(d, off, n)
    if off < 0 or off + n > d.len then
        error("geoip: read past the end")
    end
end

-- Control byte at `off`: type, size, offset of the payload.
local function control(d, off)
    bounds(d, off, 1)
    local p = d.ptr
    local ctrl = p[off]
    off = off + 1
    local t = rshift(ctrl, 5)
    if t == T_POINTER then
        return t, ctrl, off
    end
    if t == 0 then
        bounds(d, off, 1)
        t = 7 + p[off]
        off = off + 1
    end
    local size = band(ctrl, 0x1f)
    if size == 29 then
        bounds(d, off, 1)
        size = 29 + p[off]
        off = off + 1
    elseif size == 30 then
        bounds(d, off, 2)
        size = 285 + lshift(p[off], 8) + p[off + 1]
        off = off + 2
    elseif size == 31 then
        bounds(d, off, 3)
        size = 65821 + lshift(p[off], 16) + lshift(p[off + 1], 8) + p[off + 2]
        off = off + 3
    end
    return t, size, off
end

-- A pointer's target (absolute) and the offset after the pointer.
local function pointer(d, ctrl, off)
    local p = d.ptr
    local ss = band(rshift(ctrl, 3), 3)
    local v = band(ctrl, 7)
    local target
    if ss == 0 then
        bounds(d, off, 1)
        target = lshift(v, 8) + p[off]
        off = off + 1
    elseif ss == 1 then
        bounds(d, off, 2)
        target = lshift(v, 16) + lshift(p[off], 8) + p[off + 1] + 2048
        off = off + 2
    elseif ss == 2 then
        bounds(d, off, 3)
        target = lshift(v, 24) + lshift(p[off], 16) + lshift(p[off + 1], 8) + p[off + 2] + 526336
        off = off + 3
    else
        bounds(d, off, 4)
        target = p[off] * 16777216 + lshift(p[off + 1], 16) + lshift(p[off + 2], 8) + p[off + 3]
        off = off + 4
    end
    return d.data_start + target, off
end

-- The offset just after the value at `off` (a pointer is not followed).
local function skip(d, off, depth)
    if depth > 32 then
        error("geoip: data nested too deep")
    end
    local t, size, poff = control(d, off)
    if t == T_POINTER then
        local _, after = pointer(d, size, poff)
        return after
    end
    if t == T_MAP then
        for _ = 1, size * 2 do
            poff = skip(d, poff, depth + 1)
        end
        return poff
    end
    if t == T_ARRAY then
        for _ = 1, size do
            poff = skip(d, poff, depth + 1)
        end
        return poff
    end
    if t == T_BOOL then
        return poff
    end
    bounds(d, poff, size)
    return poff + size
end

-- Follow pointers from `off` to the value itself: its type, size and
-- payload offset.
local function resolve(d, off)
    local t, size, poff = control(d, off)
    if t == T_POINTER then
        local target = pointer(d, size, poff)
        t, size, poff = control(d, target)
        if t == T_POINTER then
            error("geoip: pointer to a pointer")
        end
    end
    return t, size, poff
end

-- The string at `off` (through a pointer if any), or nil.
local function string_at(d, off)
    local t, size, poff = resolve(d, off)
    if t ~= T_STRING then
        return nil
    end
    bounds(d, poff, size)
    return sub(d.buf, poff + 1, poff + size)
end

-- In the map at `off`, the offset of the value for `key`, or nil.
local function map_get(d, off, key)
    local t, size, poff = resolve(d, off)
    if t ~= T_MAP then
        return nil
    end
    for _ = 1, size do
        local k = string_at(d, poff)
        if k == nil then
            -- The format requires string keys; anything else is corrupt.
            error("geoip: map key is not a string")
        end
        poff = skip(d, poff, 0)
        if k == key then
            return poff
        end
        poff = skip(d, poff, 0)
    end
    return nil
end

-- Full decode (metadata only): strings, numbers, booleans, maps, arrays.
-- `d.budget` bounds the values decoded: pointers can share a value from
-- several places, which nesting alone would let grow exponentially.
local function decode(d, off, depth)
    if depth > 16 then
        error("geoip: metadata nested too deep")
    end
    d.budget = d.budget - 1
    if d.budget < 0 then
        error("geoip: metadata too large")
    end
    -- skip() bounds the whole value first; the bounds() below are defence
    -- in depth.
    local t, size, poff = resolve(d, off)
    local after = skip(d, off, 0)
    local p = d.ptr
    if t == T_STRING then
        bounds(d, poff, size)
        return sub(d.buf, poff + 1, poff + size), after
    elseif t == T_U16 or t == T_U32 or t == T_U64 or t == T_U128 or t == T_I32 then
        if size > 7 then
            error("geoip: integer too large")
        end
        bounds(d, poff, size)
        local v = 0
        for i = 0, size - 1 do
            v = v * 256 + p[poff + i]
        end
        return v, after
    elseif t == T_BOOL then
        return size ~= 0, after
    elseif t == T_MAP then
        local m = {}
        for _ = 1, size do
            local k = string_at(d, poff)
            if k == nil then
                error("geoip: map key is not a string")
            end
            poff = skip(d, poff, 0)
            m[k] = decode(d, poff, depth + 1)
            poff = skip(d, poff, 0)
        end
        return m, after
    elseif t == T_ARRAY then
        local a = {}
        for i = 1, size do
            a[i] = decode(d, poff, depth + 1)
            poff = skip(d, poff, 0)
        end
        return a, after
    elseif t == T_DOUBLE or t == T_FLOAT or t == T_BYTES then
        return nil, after
    end
    error("geoip: unknown data type " .. tostring(t))
end

-- ── search tree ────────────────────────────────────────────────────

local function record(d, node, b)
    local p, o = d.ptr, node * d.node_bytes
    -- walk() only asks for node < node_count, and load() checked that the
    -- tree fits the file, so this cannot fail on a loaded database: defence
    -- in depth, so no read can leave the buffer whatever changes elsewhere.
    bounds(d, o, d.node_bytes)
    local rs = d.record_size
    if rs == 24 then
        o = o + 3 * b
        return lshift(p[o], 16) + lshift(p[o + 1], 8) + p[o + 2]
    elseif rs == 28 then
        if b == 0 then
            return lshift(band(p[o + 3], 0xf0), 20) + lshift(p[o], 16) + lshift(p[o + 1], 8) + p[o + 2]
        end
        return lshift(band(p[o + 3], 0x0f), 24) + lshift(p[o + 4], 16) + lshift(p[o + 5], 8) + p[o + 6]
    end
    o = o + 4 * b
    return p[o] * 16777216 + lshift(p[o + 1], 16) + lshift(p[o + 2], 8) + p[o + 3]
end

-- Walk `nbits` bits of the big-endian byte array `bytes` from `node`.
local function walk(d, node, bytes, nbits)
    local count = d.node_count
    for i = 0, nbits - 1 do
        if node >= count then
            break
        end
        local by = bytes[rshift(i, 3) + 1]
        local b = band(rshift(by, 7 - band(i, 7)), 1)
        node = record(d, node, b)
    end
    return node
end

-- ── addresses ──────────────────────────────────────────────────────

local function parse_v4(s)
    local a, b, c, e = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    local out = { tonumber(a), tonumber(b), tonumber(c), tonumber(e) }
    for i = 1, 4 do
        if out[i] > 255 then
            return nil
        end
    end
    return out
end

local function parse_v6(s)
    if #s > 45 or not s:find(":", 1, true) or s:find("[^%x:.]") then
        return nil
    end
    local tail4
    local v4 = s:match(":(%d+%.%d+%.%d+%.%d+)$")
    if v4 then
        tail4 = parse_v4(v4)
        if not tail4 then
            return nil
        end
        s = sub(s, 1, #s - #v4) .. "0:0"
    end
    local head, rest = s, nil
    local dc = find(s, "::", 1, true)
    if dc then
        if find(s, "::", dc + 1, true) then
            return nil
        end
        head, rest = sub(s, 1, dc - 1), sub(s, dc + 2)
    end
    local function groups(x)
        local g = {}
        if x == "" then
            return g
        end
        for part in (x .. ":"):gmatch("([^:]*):") do
            local w = #part <= 4 and tonumber(part, 16)
            if not w or part:find("[^%x]") then
                return nil
            end
            g[#g + 1] = w
        end
        return g
    end
    local hg, rg = groups(head), rest and groups(rest) or {}
    if not hg or not rg then
        return nil
    end
    local missing = 8 - #hg - #rg
    if (dc and missing < 1) or (not dc and missing ~= 0) then
        return nil
    end
    local words = {}
    for _, w in ipairs(hg) do words[#words + 1] = w end
    for _ = 1, missing do words[#words + 1] = 0 end
    for _, w in ipairs(rg) do words[#words + 1] = w end
    local out = {}
    for i = 1, 8 do
        out[2 * i - 1] = rshift(words[i], 8)
        out[2 * i] = band(words[i], 0xff)
    end
    if tail4 then
        out[13], out[14], out[15], out[16] = tail4[1], tail4[2], tail4[3], tail4[4]
    end
    return out
end

-- Addresses that never identify a client's country.
local function v4_private(a)
    local x, y = a[1], a[2]
    return x == 0 or x == 10 or x == 127 or x >= 224
        or (x == 100 and y >= 64 and y <= 127)   -- CGNAT (and the overlay)
        or (x == 169 and y == 254)
        or (x == 172 and y >= 16 and y <= 31)
        or (x == 192 and y == 168)
end

local function v6_private(a)
    local zero = true
    for i = 1, 15 do
        if a[i] ~= 0 then zero = false break end
    end
    return (zero and a[16] <= 1)                   -- :: and ::1
        or band(a[1], 0xfe) == 0xfc                -- fc00::/7
        or (a[1] == 0xfe and band(a[2], 0xc0) == 0x80) -- fe80::/10
        or a[1] == 0xff                            -- multicast
end

-- ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible) are IPv4 clients;
-- :: and ::1 are not (v6_private).
local function mapped_v4(a)
    for i = 1, 10 do
        if a[i] ~= 0 then return nil end
    end
    if (a[11] == 0xff and a[12] == 0xff)
        or (a[11] == 0 and a[12] == 0 and (a[13] ~= 0 or a[14] ~= 0 or a[15] ~= 0 or a[16] > 1)) then
        return { a[13], a[14], a[15], a[16] }
    end
    return nil
end

-- ── public API ─────────────────────────────────────────────────────

-- Load the database at `path`. Returns true and a description, or nil
-- and the reason; on failure every lookup answers "XX".
function M.load(path)
    db = nil
    local f, err = io.open(path, "rb")
    if not f then
        return nil, "cannot open " .. tostring(path) .. ": " .. tostring(err)
    end
    local buf = f:read("*a")
    f:close()
    if type(buf) ~= "string" then
        return nil, "cannot read " .. tostring(path)
    end
    return M.load_bytes(buf)
end

-- Reads past the buffer seen in checked mode (tests only): every read is
-- meant to be preceded by bounds(), so this must stay 0.
M.unchecked_reads = 0

-- A byte "pointer" that verifies every index (tests only).
local function checked_ptr(buf)
    local len = #buf
    return setmetatable({}, { __index = function(_, i)
        if type(i) ~= "number" or i < 0 or i >= len or i % 1 ~= 0 then
            M.unchecked_reads = M.unchecked_reads + 1
            error("geoip: unchecked read at " .. tostring(i))
        end
        return byte(buf, i + 1)
    end })
end

-- Load a database from its bytes (M.load; the fuzz test). Never throws.
-- `checked` (tests only) reads through a verifying proxy instead of FFI.
function M.load_bytes(buf, checked)
    db = nil
    local ok, r1, r2 = pcall(function()
        return M._parse(buf, checked)
    end)
    if not ok then
        return nil, "bad database: " .. tostring(r1)
    end
    if type(r1) ~= "table" then
        return nil, r2
    end
    db = r1
    return true, r2
end

function M._parse(buf, checked)
    local d = { buf = buf, len = #buf, data_start = 0 }
    d.ptr = checked and checked_ptr(buf) or ffi.cast("const uint8_t *", buf)
    local from = math.max(1, #buf - METADATA_MAX)
    local at, last = nil, nil
    repeat
        last = at
        at = find(buf, MARKER, (at and at + 1) or from, true)
    until not at
    if not last then
        return nil, "no MaxMind metadata"
    end
    local ok, meta = pcall(function()
        -- Metadata pointers (none in practice) are relative to its start.
        d.data_start = last - 1 + #MARKER
        d.budget = 10000
        local m = decode(d, d.data_start, 0)
        d.data_start = 0
        return m
    end)
    if not ok or type(meta) ~= "table" then
        return nil, "bad metadata: " .. tostring(meta)
    end
    if meta.binary_format_major_version ~= 2 then
        return nil, "unsupported format version"
    end
    local rs, count, ipv = meta.record_size, meta.node_count, meta.ip_version
    if (rs ~= 24 and rs ~= 28 and rs ~= 32) or type(count) ~= "number" or count < 1
        or (ipv ~= 4 and ipv ~= 6) then
        return nil, "bad metadata values"
    end
    d.record_size, d.node_count, d.ip_version = rs, count, ipv
    d.node_bytes = rs * 2 / 8
    local tree = count * d.node_bytes
    if tree + 16 > last - 1 then
        return nil, "search tree larger than the file"
    end
    d.data_start = tree + 16
    d.data_end = last - 1
    -- IPv4 lookups in an IPv6 tree start below ::/96.
    d.v4_node = 0
    if ipv == 6 then
        local zeros = {}
        for i = 1, 12 do zeros[i] = 0 end
        d.v4_node = walk(d, 0, zeros, 96)
    end
    d.regions = {} -- data offset → region, bounded by the distinct records
    d.meta = meta
    local built = os.date("!%Y-%m-%d", tonumber(meta.build_epoch) or 0)
    return d, string.format("%s, %d nodes, built %s", tostring(meta.database_type),
        count, tostring(built))
end

function M.loaded()
    return db ~= nil
end

local function region_at(d, off)
    local cached = d.regions[off]
    if cached then
        return cached
    end
    local r = M.UNKNOWN
    local country = map_get(d, off, "country")
    local iso = country and map_get(d, country, "iso_code")
    local code = iso and string_at(d, iso)
    if code then
        code = code:upper()
        if code:match("^[A-Z][A-Z]$") and code ~= "ZZ" and code ~= "XX" then
            r = code
        end
    end
    d.regions[off] = r
    return r
end

local function lookup(d, addr)
    local a = parse_v4(addr)
    local node, bytes, nbits
    if a then
        if v4_private(a) then
            return M.UNKNOWN
        end
        node, bytes, nbits = d.v4_node, a, 32
    else
        a = parse_v6(addr)
        if not a then
            return M.UNKNOWN
        end
        local m = mapped_v4(a)
        if m then
            if v4_private(m) then
                return M.UNKNOWN
            end
            node, bytes, nbits = d.v4_node, m, 32
        elseif v6_private(a) or d.ip_version == 4 then
            return M.UNKNOWN
        else
            node, bytes, nbits = 0, a, 128
        end
    end
    node = walk(d, node, bytes, nbits)
    if node <= d.node_count then
        return M.UNKNOWN
    end
    local off = node - d.node_count - 16 + d.data_start
    if off < d.data_start or off >= d.data_end then
        return M.UNKNOWN
    end
    return region_at(d, off)
end

-- The client's region for `addr` (an address string), never an error.
function M.country(addr)
    local d = db
    if d == nil or type(addr) ~= "string" then
        return M.UNKNOWN
    end
    local ok, r = pcall(lookup, d, addr)
    if ok and r then
        return r
    end
    return M.UNKNOWN
end

return M
