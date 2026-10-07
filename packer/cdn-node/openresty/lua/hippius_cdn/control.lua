-- The control socket handler (`listen unix:/run/cdn/ctl.sock` only).
--
-- PUT /v1/<document> with a full JSON document. 204 when stored, 400 when
-- it does not validate (nothing stored), 409 on PUT /v1/health while the
-- shared memory lacks config/secrets/certs (OpenResty restarted: the
-- agent re-pushes everything). The body never touches disk: the control
-- server's client_body_buffer_size equals client_max_body_size.
local docs = require("hippius_cdn.docs")

local M = {}

local function reply(status, msg)
    ngx.status = status
    if msg then
        ngx.header["Content-Type"] = "text/plain"
        ngx.say(msg)
    end
    return ngx.exit(status)
end

function M.handle()
    if ngx.req.get_method() ~= "PUT" then
        return reply(405, "method")
    end
    local name = ngx.var.uri:match("^/v1/([a-z]+)$")
    if not name or not docs.NAMES[name] then
        return reply(404, "unknown-document")
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw then
        -- Either empty, or spilled to a temp file (refused: secrets must
        -- stay in memory; the buffer size makes this unreachable).
        return reply(400, "body")
    end
    local derived, why = docs.validate(name, raw)
    if not derived then
        ngx.log(ngx.WARN, "hippius-cdn: control document ", name, " refused: ", why)
        return reply(400, why)
    end
    local ok, err = docs.store(name, raw)
    if not ok then
        ngx.log(ngx.ERR, "hippius-cdn: control document ", name, " not stored: ", err)
        return reply(507, err)
    end
    if name == "health" and not docs.all_required_present() then
        return reply(409, "resync")
    end
    return reply(204)
end

return M
