-- Node-wide settings, fixed at nginx start (init_by_lua) from the
-- rendered nginx.conf. Nothing here comes from the feed.
local M = {
    meter_socket = "/run/cdn-agent/meter.sock",
    cache_dir = "/var/lib/hippius-data/cache",
    -- The agent pushes health every 5 s; a document older than this
    -- means the agent is gone and the node is not ready.
    health_max_age = 30,
    -- Worker 0 re-checks (and rewrites if needed) the cache canary this
    -- often, in seconds.
    canary_interval = 10,
    -- nginx's mime.types (Content-Type fallback by extension).
    mime_types = "/opt/openresty/nginx/conf/mime.types",
    -- Edge and browser lifetime of a 200/206, in seconds: nginx's
    -- proxy_cache_valid for those statuses, until zone rules set it.
    default_ttl = 3600,
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
