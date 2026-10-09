-- A zone's hard ceilings (feed `settings.limits`, contract C.4 "Zone
-- settings"): `max_mbps` (megabits per second of bytes out) and `max_rps`
-- (requests per second), set by support. Integers >= 0; 0 is no allowance
-- at all. Over a ceiling, new requests get 503; responses in flight finish.
--
-- Enforced PER NODE: every node applies the whole ceiling to the traffic it
-- serves itself, with no coordination between nodes. A zone served by N
-- nodes can therefore reach up to N times a ceiling across the fleet.
--
-- Counters live in a shared dict (all workers), in one-second windows:
--   r:<zone>:<second>  requests admitted in that second
--   b:<zone>:<second>  body bytes sent in that second (counted as they are
--                      sent, so a long download counts while it runs;
--                      bytes before gzip)
local M = {}

M.DEFAULT_MBPS = 2000
M.DEFAULT_RPS = 20000
-- A ceiling above this is treated as this (no node gets near it).
local MAX_VALUE = 10000000

local null = (require("cjson.safe")).null

local function value(v, default)
    if v == nil or v == null then
        return default
    end
    if type(v) ~= "number" or v < 0 or v % 1 ~= 0 then
        return nil
    end
    return math.min(v, MAX_VALUE)
end

-- The ceilings of a zone's `settings` (`{mbps, rps}`), and whether the
-- limits object was usable (an unusable one falls back to the defaults).
function M.of(settings_doc)
    local l = type(settings_doc) == "table" and settings_doc.limits or nil
    if l == nil or l == null then
        return { mbps = M.DEFAULT_MBPS, rps = M.DEFAULT_RPS }, true
    end
    if type(l) ~= "table" then
        return { mbps = M.DEFAULT_MBPS, rps = M.DEFAULT_RPS }, false
    end
    local mbps, rps = value(l.max_mbps, M.DEFAULT_MBPS), value(l.max_rps, M.DEFAULT_RPS)
    if mbps == nil or rps == nil then
        return { mbps = M.DEFAULT_MBPS, rps = M.DEFAULT_RPS }, false
    end
    return { mbps = mbps, rps = rps }, true
end

-- Whether a new request of `zone_id` is admitted under `lim` at `now`
-- (whole seconds) with counters in `dict`. Returns true, or false and the
-- ceiling that refused it ("rps" | "mbps"). A request it admits counts.
function M.admit(dict, zone_id, lim, now)
    if lim.rps == 0 then
        return false, "rps"
    end
    if lim.mbps == 0 then
        return false, "mbps"
    end
    -- Bandwidth: the current or the previous second over the ceiling.
    local ceiling = lim.mbps * 125000 -- bytes per second
    local cur = dict:get("b:" .. zone_id .. ":" .. now) or 0
    local prev = dict:get("b:" .. zone_id .. ":" .. (now - 1)) or 0
    if cur > ceiling or prev > ceiling then
        return false, "mbps"
    end
    local n, err = dict:incr("r:" .. zone_id .. ":" .. now, 1, 0, 2)
    if err and ngx and ngx.log then
        ngx.log(ngx.CRIT, "hippius-cdn: zone ", zone_id, " request not counted: ", err)
    end
    if n and n > lim.rps then
        return false, "rps"
    end
    return true
end

-- Count `nbytes` of body sent for `zone_id` at `now`.
function M.account(dict, zone_id, nbytes, now)
    if nbytes > 0 then
        local _, err = dict:incr("b:" .. zone_id .. ":" .. now, nbytes, 0, 3)
        if err and ngx and ngx.log then
            ngx.log(ngx.CRIT, "hippius-cdn: zone ", zone_id, " bytes not counted: ", err)
        end
    end
end

return M
