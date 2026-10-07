-- /__hippius/health (spec §7.3), the ACME HTTP-01 responder and the
-- attestation document. All three answer for any Host and are never
-- billable.
local cjson = require("cjson.safe")
local docs = require("hippius_cdn.docs")
local settings = require("hippius_cdn.settings")

local M = {}

M.CANARY_BODY = "hippius-canary\n"

local function canary_path()
    return settings.cache_dir .. "/.hippius-canary"
end

-- Worker 0 writes the canary on the cache volume at start. Health then
-- reads it back through nginx: a missing or unreadable volume fails it.
function M.write_canary()
    if ngx.worker.id() ~= 0 then
        return
    end
    ngx.timer.at(0, function(premature)
        if premature then
            return
        end
        local f, err = io.open(canary_path(), "w")
        if not f then
            ngx.log(ngx.ERR, "hippius-cdn: canary write failed: ", err)
            return
        end
        f:write(M.CANARY_BODY)
        f:close()
    end)
end

-- The verdict, pure on its inputs (unit-tested).
function M.verdict(health_doc, now, canary_ok)
    local agent_ready = health_doc ~= nil and health_doc.ready == true
    local fresh = health_doc ~= nil and type(health_doc.at) == "number"
        and now - health_doc.at <= settings.health_max_age and now - health_doc.at >= -settings.health_max_age
    local ok = agent_ready and fresh and canary_ok
    return ok, { agent_ready = agent_ready, fresh = fresh, canary = canary_ok }
end

function M.serve()
    local h = docs.get("health")
    local res = ngx.location.capture("/__hippius/canary")
    local canary_ok = res and res.status == 200 and res.body == M.CANARY_BODY
    local ok, detail = M.verdict(h and h.doc, ngx.time(), canary_ok)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "application/json"
    ngx.status = ok and 200 or 503
    ngx.say(cjson.encode(detail))
    return ngx.exit(ngx.status)
end

function M.acme()
    local token = ngx.var.uri:match("^/%.well%-known/acme%-challenge/([A-Za-z0-9_-]+)$")
    local cfg = docs.get("config")
    local keyauth = token and cfg and cfg.acme[token]
    if not keyauth then
        return ngx.exit(404)
    end
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(keyauth)
    return ngx.exit(200)
end

function M.attestation()
    local a = docs.get("attestation")
    if not a then
        return ngx.exit(404)
    end
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(cjson.encode(a.doc))
    return ngx.exit(200)
end

return M
