-- Node-wide settings, fixed at nginx start (init_by_lua) from the
-- rendered nginx.conf. Nothing here comes from the feed.
local M = {
    meter_socket = "/run/cdn-agent/meter.sock",
    cache_dir = "/var/lib/hippius-data/cache",
    -- The agent pushes health every 5 s; a document older than this
    -- means the agent is gone and the node is not ready.
    health_max_age = 30,
    -- Default S3 region for SigV4 when a zone's origin names none.
    s3_region = "us-east-1",
    -- Lifetime of the presigned origin URL: covers every slice of one
    -- download. It never leaves the node (TLS to the origin only).
    presign_expires = 86400,
    -- Per-worker cap on metering records waiting for the sender timer.
    meter_queue_max = 50000,
}

function M.set(values)
    for k, v in pairs(values) do
        if M[k] == nil then
            error("hippius_cdn.settings: unknown key " .. tostring(k))
        end
        M[k] = v
    end
end

return M
