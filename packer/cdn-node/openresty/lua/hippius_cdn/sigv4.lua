-- AWS Signature Version 4 for the S3 origin: presigned GET object.
-- HMAC-SHA256 is built on resty.sha256 (OpenResty ships no HMAC-SHA256).
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")
local bit = require("bit")

local M = {}

local byte, char, rep = string.byte, string.char, string.rep
local to_hex = resty_string.to_hex

local function sha256(s)
    local h = resty_sha256:new()
    h:update(s)
    return h:final()
end
M.sha256_hex = function(s)
    return to_hex(sha256(s))
end

local function xor_pad(key, pad)
    local out = {}
    for i = 1, 64 do
        out[i] = char(bit.bxor(byte(key, i), pad))
    end
    return table.concat(out)
end

function M.hmac_sha256(key, msg)
    if #key > 64 then
        key = sha256(key)
    end
    key = key .. rep("\0", 64 - #key)
    return sha256(xor_pad(key, 0x5c) .. sha256(xor_pad(key, 0x36) .. msg))
end

local function q_encode(v)
    return (v:gsub("[^A-Za-z0-9%-%._~]", function(c)
        return string.format("%%%02X", byte(c))
    end))
end

local function signing_key(secret, date, region, service)
    local k = M.hmac_sha256("AWS4" .. secret, date)
    k = M.hmac_sha256(k, region)
    k = M.hmac_sha256(k, service)
    return M.hmac_sha256(k, "aws4_request")
end

-- A presigned (query-string) GET, signing only `host` with an unsigned
-- payload. Returns the query string, signature included. A presigned
-- request is valid for `expires` seconds from `amz_date` rather than a
-- clock-skew window around it, so every slice of a long download can
-- reuse the one signature the main request made: slice subrequests skip
-- the Lua phases and cannot re-sign.
function M.presign(args)
    local date = args.amz_date:sub(1, 8)
    local scope = date .. "/" .. args.region .. "/" .. args.service .. "/aws4_request"
    local params = {
        { "X-Amz-Algorithm", "AWS4-HMAC-SHA256" },
        { "X-Amz-Credential", args.access_key .. "/" .. scope },
        { "X-Amz-Date", args.amz_date },
        { "X-Amz-Expires", tostring(args.expires) },
        { "X-Amz-SignedHeaders", "host" },
    }
    if args.session_token then
        params[#params + 1] = { "X-Amz-Security-Token", args.session_token }
    end
    table.sort(params, function(a, b)
        return a[1] < b[1]
    end)
    local parts = {}
    for i, kv in ipairs(params) do
        parts[i] = q_encode(kv[1]) .. "=" .. q_encode(kv[2])
    end
    local query = table.concat(parts, "&")
    local creq = table.concat({
        args.method, args.uri, query, "host:" .. args.host .. "\n", "host", "UNSIGNED-PAYLOAD",
    }, "\n")
    local sts = "AWS4-HMAC-SHA256\n" .. args.amz_date .. "\n" .. scope .. "\n" .. to_hex(sha256(creq))
    local key = signing_key(args.secret_key, date, args.region, args.service)
    return query .. "&X-Amz-Signature=" .. to_hex(M.hmac_sha256(key, sts))
end

-- `20151230T120000Z` for a Unix time.
function M.amz_date(t)
    return os.date("!%Y%m%dT%H%M%SZ", t)
end

return M
