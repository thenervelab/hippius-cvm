-- Per-request metering records for the agent (spec §9.1).
--
-- The log phase cannot use cosockets, so each worker queues records in
-- memory and a 100 ms timer sends them, one JSON object per datagram, to
-- the agent's Unix datagram socket. The record format is the agent's
-- RequestRecord (closed field set). A full queue drops and counts.
local cjson = require("cjson.safe")
local geoip = require("hippius_cdn.geoip")
local settings = require("hippius_cdn.settings")
local util = require("hippius_cdn.util")

local M = {}

local queue, head, tail = {}, 1, 0
local dropped = 0

local CACHE_STATUS = {
    HIT = "hit", MISS = "miss", BYPASS = "bypass", EXPIRED = "expired",
    STALE = "stale", UPDATING = "updating", REVALIDATED = "revalidated",
}
M.CACHE_STATUS = CACHE_STATUS

-- Build the record for the current request (pure on its inputs, so it
-- is unit-tested): `ctx` is ngx.ctx, `var` is ngx.var, `status` ngx.status.
-- Origin bytes this request (or subrequest) fetched itself: none on a hit.
local function own_origin_bytes(var)
    local cache = CACHE_STATUS[var.upstream_cache_status or ""]
    if cache == nil or cache == "miss" or cache == "expired" or cache == "bypass"
        or cache == "revalidated" or cache == "updating" then
        return util.sum_list(var.upstream_bytes_received)
    end
    return 0
end

function M.record(ctx, var, status)
    local cache = CACHE_STATUS[var.upstream_cache_status or ""]
    -- The main request fetched the first slice; later slices added theirs
    -- to $hippius_origin_bytes as they finished (see M.log).
    local from_origin = own_origin_bytes(var) + (tonumber(var.hippius_origin_bytes) or 0)
    if status == nil or status < 100 or status > 599 then
        status = 499
    end
    return {
        zone = ctx.zone,
        client_region = ctx.client_region or "XX",
        -- Only a request that passed every check of a known zone is
        -- billable; everything the node answered itself is not.
        billable = ctx.billable == true and ctx.zone ~= nil,
        bytes_out = tonumber(var.bytes_sent) or 0,
        cache = cache,
        bytes_from_origin = from_origin,
        bytes_from_shield = 0,
        status = status,
    }
end

function M.log()
    -- Slice subrequests (log_subrequest on) emit no record: they add the
    -- origin bytes they fetched to the variable they share with the main
    -- request, which is logged last.
    if ngx.is_subrequest then
        local var = ngx.var
        local n = own_origin_bytes(var)
        if n > 0 and var.hippius_origin_bytes ~= nil then
            var.hippius_origin_bytes = (tonumber(var.hippius_origin_bytes) or 0) + n
        end
        return
    end
    if tail - head + 1 >= settings.meter_queue_max then
        dropped = dropped + 1
        return
    end
    local ctx = ngx.ctx
    -- The node has its own public IP: $remote_addr is the client.
    ctx.client_region = geoip.country(ngx.var.remote_addr)
    local rec = cjson.encode(M.record(ctx, ngx.var, ngx.status))
    if rec and #rec <= 2048 then
        tail = tail + 1
        queue[tail] = rec
    end
end

local function flush(premature)
    if premature or tail < head then
        return
    end
    local sock = ngx.socket.udp()
    local ok, err = sock:setpeername("unix:" .. settings.meter_socket)
    if not ok then
        dropped = dropped + (tail - head + 1)
        queue, head, tail = {}, 1, 0
        ngx.log(ngx.WARN, "hippius-cdn: metering socket: ", err, ", dropped ", dropped)
        return
    end
    while head <= tail do
        local rec = queue[head]
        queue[head] = nil
        head = head + 1
        local sent = sock:send(rec)
        if not sent then
            dropped = dropped + 1
        end
    end
    queue, head, tail = {}, 1, 0
    sock:close()
end

function M.start()
    local ok, err = ngx.timer.every(0.1, flush)
    if not ok then
        ngx.log(ngx.ERR, "hippius-cdn: metering timer: ", err)
    end
end

function M.dropped()
    return dropped
end

return M
