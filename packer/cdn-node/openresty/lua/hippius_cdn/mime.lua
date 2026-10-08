-- Content-Type fallback by extension, from the mime.types file the
-- OpenResty build ships (loaded once, at init_by_lua, in the master).
--
-- Used only when the origin declares no type, or a generic octet-stream.
-- It only ever yields a type from a short allowlist of families a browser
-- does not render as a script-capable document: never HTML, SVG or any
-- XML. A type the origin declares is kept, and a script-capable one is
-- sandboxed (csp_for). Anything else falls back to
-- application/octet-stream.
local M = {}

local by_ext = {}

M.OCTET = "application/octet-stream"

-- Types a browser may render as a script-capable document: HTML, any XML
-- (XHTML and SVG run script; XSLT can turn XML into HTML), XSLT itself,
-- MathML. `t` may carry parameters.
local SCRIPT_CAPABLE = {
    ["text/html"] = true,
    ["text/xsl"] = true,
    ["text/mathml"] = true,
}

function M.script_capable(t)
    t = (t:match("^%s*([^;%s]+)") or t):lower()
    return SCRIPT_CAPABLE[t] or t:find("xml", 1, true) ~= nil
end

-- On the fleet's shared domain (every zone is <id>.c.hipcdn.net, so zones
-- are same-site with each other), a script-capable response runs in an
-- opaque origin: classic scripts run, but it cannot read or write cookies
-- or use storage. The opaque origin also makes its same-host requests
-- cross-origin (module scripts, fonts, fetch), which this data plane does
-- not answer with CORS: such a site needs a custom domain, where the
-- router does not sandbox.
M.SANDBOX = "sandbox allow-scripts"

-- The Content-Security-Policy for a response of type `t`, or nil.
function M.csp_for(t)
    if t ~= nil and M.script_capable(t) then
        return M.SANDBOX
    end
    return nil
end

local SAFE_FAMILIES = { "image/", "audio/", "video/", "font/" }
local SAFE_TYPES = {
    ["text/css"] = true,
    ["text/plain"] = true,
    ["text/javascript"] = true,
    ["application/javascript"] = true,
    ["application/json"] = true,
    ["application/wasm"] = true,
}

-- Whether the fallback may yield `t`.
function M.fallback_allowed(t)
    t = t:lower()
    if M.script_capable(t) then
        return false
    end
    if SAFE_TYPES[t] then
        return true
    end
    for _, family in ipairs(SAFE_FAMILIES) do
        if t:sub(1, #family) == family then
            return true
        end
    end
    return false
end

-- Parse nginx's mime.types: `type ext1 ext2 ...;` statements inside
-- `types { }`, an entry possibly spanning lines.
function M.parse(text)
    local map = {}
    local body = text:gsub("#[^\n]*", ""):match("types%s*{(.*)}") or ""
    for stmt in body:gmatch("([^;]+);") do
        local t, exts = stmt:match("^%s*([%w%.%+%-]+/[%w%.%+%-]+)%s+(.+)$")
        if t then
            for ext in exts:gmatch("%S+") do
                map[ext:lower()] = t
            end
        end
    end
    return map
end

function M.load(path)
    local f, err = io.open(path, "r")
    if not f then
        error("hippius_cdn.mime: cannot read " .. path .. ": " .. tostring(err))
    end
    local text = f:read("*a")
    f:close()
    by_ext = M.parse(text)
end

local GENERIC = {
    ["application/octet-stream"] = true,
    ["binary/octet-stream"] = true,
}

-- The Content-Type to send for `path` given what the origin declared
-- (nil when it sent none). Returns nil to keep the declared type.
function M.fallback(path, declared)
    if declared ~= nil and declared:match("%S") then
        local base = declared:match("^%s*([^;%s]+)") or declared
        if not GENERIC[base:lower()] then
            return nil
        end
    end
    local ext = path:match("%.([%w]+)$")
    local t = ext and by_ext[ext:lower()]
    if not t or not M.fallback_allowed(t) then
        return M.OCTET
    end
    return t
end

return M
