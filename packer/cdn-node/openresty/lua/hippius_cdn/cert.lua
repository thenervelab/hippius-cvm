-- ssl_certificate_by_lua: pick the certificate for the SNI name from the
-- agent's certs document (exact name, then its wildcard, then the fleet
-- wildcard default). With no match the handshake is refused: no node
-- ever presents a certificate it does not hold.
local ssl = require("ngx.ssl")
local docs = require("hippius_cdn.docs")
local util = require("hippius_cdn.util")

local M = {}

local function parsed(store, name)
    local p = store.parsed[name]
    if p then
        return p
    end
    local entry = store.doc.certs[name]
    local chain, err1 = ssl.parse_pem_cert(entry.chain_pem)
    local key, err2 = ssl.parse_pem_priv_key(entry.key_pem)
    if not chain or not key then
        ngx.log(ngx.ERR, "hippius-cdn: unusable certificate for ", name, ": ", err1 or err2)
        return nil
    end
    p = { chain = chain, key = key }
    store.parsed[name] = p
    return p
end

function M.select(store, sni)
    local certs = store.doc.certs
    if sni then
        if certs[sni] then
            return sni
        end
        local wc = util.wildcard_of(sni)
        if wc and certs[wc] then
            return wc
        end
    end
    return store.default
end

function M.serve()
    local store = docs.get("certs")
    if not store then
        return ngx.exit(ngx.ERROR)
    end
    local sni = ssl.server_name()
    sni = sni and sni:lower() or nil
    local name = M.select(store, sni)
    local p = name and parsed(store, name)
    if not p then
        return ngx.exit(ngx.ERROR)
    end
    local ok, err = ssl.clear_certs()
    if ok then
        ok, err = ssl.set_cert(p.chain)
    end
    if ok then
        ok, err = ssl.set_priv_key(p.key)
    end
    if not ok then
        ngx.log(ngx.ERR, "hippius-cdn: certificate install failed: ", err)
        return ngx.exit(ngx.ERROR)
    end
end

return M
