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

-- Make sure the canary at `path` holds CANARY_BODY, writing it when it
-- is missing or wrong. Returns true, or nil and the error.
function M.ensure_canary(path)
    local f = io.open(path, "r")
    if f then
        local body = f:read("*a")
        f:close()
        if body == M.CANARY_BODY then
            return true
        end
    end
    local w, err = io.open(path, "w")
    if not w then
        return nil, err
    end
    local ok, werr = w:write(M.CANARY_BODY)
    local closed, cerr = w:close()
    if not ok or not closed then
        return nil, werr or cerr
    end
    return true
end

-- Whether the last check failed (nil before the first one).
local canary_failing = nil

-- One check, logged only when the outcome changes. `log(level, msg)`.
function M.canary_tick(path, log)
    local ok, err = M.ensure_canary(path)
    if not ok and canary_failing ~= true then
        log(ngx.ERR, "hippius-cdn: canary write failed: " .. tostring(err))
    elseif ok and canary_failing == true then
        log(ngx.WARN, "hippius-cdn: canary written again")
    end
    canary_failing = not ok
    return ok
end

-- For the unit tests.
function M.reset_canary_state()
    canary_failing = nil
end

-- Worker 0 keeps the canary on the cache volume: at start, then every
-- canary_interval seconds, so a volume that comes up late or a file that
-- disappears heals on its own. Health reads it back through nginx: a
-- missing or unreadable volume fails it.
function M.write_canary()
    if ngx.worker.id() ~= 0 then
        return
    end
    local function tick(premature)
        if premature then
            return
        end
        M.canary_tick(canary_path(), ngx.log)
    end
    ngx.timer.at(0, tick)
    local ok, err = ngx.timer.every(settings.canary_interval, tick)
    if not ok then
        ngx.log(ngx.ERR, "hippius-cdn: canary timer failed: ", err)
    end
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
