-- Lua unit tests, run with the OpenResty `resty` CLI:
--   resty -I packer/cdn-node/openresty/lua packer/cdn-node/openresty/tests/unit/run.lua
-- A minimal harness: each test is a function; any error fails the run.
local util = require("hippius_cdn.util")
local sigv4 = require("hippius_cdn.sigv4")
local meter = require("hippius_cdn.meter")
local health = require("hippius_cdn.health")
local docs = require("hippius_cdn.docs")
local router = require("hippius_cdn.router")
local cert = require("hippius_cdn.cert")
local settings = require("hippius_cdn.settings")
local cjson = require("cjson.safe")
local rstr = require("resty.string")

local tests, failures = {}, 0
local function test(name, fn) tests[#tests + 1] = { name, fn } end
local function eq(a, b, msg)
    if a ~= b then
        error((msg or "") .. ": expected " .. tostring(b) .. ", got " .. tostring(a), 2)
    end
end
local function truthy(v, msg) if not v then error(msg or "expected true", 2) end end
local function falsy(v, msg) if v then error(msg or "expected false", 2) end end

test("valid_host", function()
    truthy(util.valid_host("img.example.com"))
    truthy(util.valid_host("a-1.b.co"))
    for _, h in ipairs({ "", "localhost", "Img.example.com", "-a.example.com", "a..b.com",
        "a.b.com.", "1.2.3.4", "exa mple.com", "a_b.example.com", string.rep("a", 64) .. ".com" }) do
        falsy(util.valid_host(h), h)
    end
end)

test("valid_path refuses dot segments and control bytes", function()
    truthy(util.valid_path("/a/b.txt"))
    truthy(util.valid_path("/a/.hidden/..x"))
    for _, p in ipairs({ "a/b", "/a/../b", "/..", "/./a", "/a/.", "/a\\b", "/a\0b", "/a\nb" }) do
        falsy(util.valid_path(p), p)
    end
end)

test("encode_path keeps unreserved and slash", function()
    eq(util.encode_path("/b/a b/ü?#%+.txt"), "/b/a%20b/%C3%BC%3F%23%25%2B.txt")
    eq(util.encode_path("/A-z_0.9~/"), "/A-z_0.9~/")
end)

test("bucket and prefix rules mirror the agent", function()
    truthy(util.valid_bucket("media"))
    falsy(util.valid_bucket("Media"))
    falsy(util.valid_bucket("ab"))
    truthy(util.valid_prefix(nil))
    truthy(util.valid_prefix("site/v1/"))
    for _, p in ipairs({ "/abs/", "../x/", "a/./b/", "a/?x/", "a/%2e/", "a b/", "a\\b/", "site", "site/v1" }) do
        falsy(util.valid_prefix(p), p)
    end
end)

test("canonical feed paths match nginx's decoded $uri", function()
    eq(util.canonical_feed_path("/a%20b.txt"), "/a b.txt")
    eq(util.canonical_feed_path("/a+b"), "/a+b", "plus is not a space in a path")
    eq(util.canonical_feed_path("/a%2Fb//c"), "/a/b/c")
    eq(util.canonical_feed_path("/%C3%BC/"), "/\195\188/")
    eq(util.canonical_feed_path("/a/%2e%2e/b"), nil)
    eq(util.canonical_feed_path("/a%00b"), nil)
    eq(util.canonical_feed_path("relative"), nil)
end)

test("purge prefixes are the ancestor directories", function()
    eq(table.concat(util.purge_prefixes("/a/b/c.jpg"), " "), "/ /a/ /a/b/")
    eq(table.concat(util.purge_prefixes("/"), " "), "/")
    eq(table.concat(util.purge_prefixes("/a/"), " "), "/ /a/")
end)

test("cache key changes with the zone and prefix generations only", function()
    local base = util.cache_key_material("z1", { zone_generation = 4, prefixes = { ["/img/"] = 2 } }, "/img/a.png")
    eq(base, table.concat({ "v2", "z1", "4", "0,2", "0", "/img/a.png" }, "\0"))
    local bumped = util.cache_key_material("z1", { zone_generation = 4, prefixes = { ["/img/"] = 3 } }, "/img/a.png")
    truthy(base ~= bumped)
    local other = util.cache_key_material("z1", { zone_generation = 4, prefixes = { ["/img/"] = 3 } }, "/css/a.css")
    eq(other, util.cache_key_material("z1", { zone_generation = 4, prefixes = { ["/img/"] = 2 } }, "/css/a.css"),
        "an unrelated prefix purge leaves other paths alone")
    eq(util.cache_key_material("z9", nil, "/x"), table.concat({ "v2", "z9", "0", "0", "0", "/x" }, "\0"))
    -- An exact-path purge changes that path's key only.
    local p = { zone_generation = 4, prefixes = {}, paths = { ["/img/a.png"] = 1 } }
    truthy(util.cache_key_material("z1", p, "/img/a.png")
        ~= util.cache_key_material("z1", { zone_generation = 4 }, "/img/a.png"))
    eq(util.cache_key_material("z1", p, "/img/a.png.bak"),
        util.cache_key_material("z1", { zone_generation = 4 }, "/img/a.png.bak"), "exact, not a prefix")
end)

test("wildcard_of and sum_list", function()
    eq(util.wildcard_of("a.b.c"), "*.b.c")
    eq(util.sum_list("10, 20 : 5"), 35)
    eq(util.sum_list(nil), 0)
end)

test("hmac-sha256 RFC 4231 vectors", function()
    eq(rstr.to_hex(sigv4.hmac_sha256(string.rep("\11", 20), "Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    eq(rstr.to_hex(sigv4.hmac_sha256(string.rep("\170", 131),
        "Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
end)

test("presigned GET matches the AWS documentation example", function()
    -- AWS S3 docs, "Authenticating Requests: Using Query Parameters":
    -- published example credentials, not a real key.
    local aws_doc_example = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    local q = sigv4.presign({
        method = "GET", uri = "/test.txt", host = "examplebucket.s3.amazonaws.com",
        amz_date = "20130524T000000Z", expires = 86400, region = "us-east-1", service = "s3",
        access_key = "AKIAIOSFODNN7EXAMPLE", secret_key = aws_doc_example,
    })
    eq(q, "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        .. "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        .. "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
        .. "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404")
    eq(sigv4.amz_date(1440938160), "20150830T123600Z")
    -- A session token is signed in, in sorted order.
    local t = sigv4.presign({
        method = "GET", uri = "/x", host = "h", amz_date = "20130524T000000Z", expires = 60,
        region = "us-east-1", service = "s3", access_key = "AK", secret_key = "s", session_token = "a/b+c",
    })
    truthy(t:find("&X-Amz-Security-Token=a%2Fb%2Bc&X-Amz-SignedHeaders=host&X-Amz-Signature=", 1, true), t)
end)

test("meter record classification", function()
    local r = meter.record({ zone = "z1", billable = true },
        { upstream_cache_status = "MISS", bytes_sent = "1234", upstream_bytes_received = "900" }, 200)
    eq(r.zone, "z1"); eq(r.billable, true); eq(r.cache, "miss"); eq(r.bytes_out, 1234)
    eq(r.bytes_from_origin, 900); eq(r.client_region, "XX"); eq(r.status, 200)
    local hit = meter.record({ zone = "z1", billable = true },
        { upstream_cache_status = "HIT", bytes_sent = "10", upstream_bytes_received = "900" }, 200)
    eq(hit.bytes_from_origin, 0, "a hit fetched nothing")
    local sliced = meter.record({ zone = "z1", billable = true },
        { upstream_cache_status = "MISS", bytes_sent = "10", upstream_bytes_received = "100",
          hippius_origin_bytes = "250" }, 200)
    eq(sliced.bytes_from_origin, 350, "later slices add theirs")
    local refused = meter.record({ zone = "z1", billable = false }, { bytes_sent = "50" }, 503)
    eq(refused.billable, false); eq(refused.cache, nil)
    local nozone = meter.record({ billable = true }, { bytes_sent = "5" }, 421)
    eq(nozone.billable, false, "no zone is never billable"); eq(nozone.zone, nil)
    eq(meter.record({}, {}, 0).status, 499)
    -- The encoded record carries only the agent's fields.
    local enc = cjson.decode(cjson.encode(r))
    local n = 0
    for k in pairs(enc) do
        n = n + 1
        truthy(({ zone = 1, client_region = 1, billable = 1, bytes_out = 1, cache = 1,
            bytes_from_origin = 1, bytes_from_shield = 1, status = 1 })[k], k)
    end
    eq(n, 8)
end)

test("canary heals and logs only state changes", function()
    local dir = os.tmpname()
    os.remove(dir)
    local path = dir .. "/.hippius-canary"
    local logged = {}
    local function log(level, msg) logged[#logged + 1] = { level, msg } end
    health.reset_canary_state()
    -- The cache directory is not there yet: fails, logged once.
    falsy(health.canary_tick(path, log))
    falsy(health.canary_tick(path, log))
    eq(#logged, 1, "one failure line")
    eq(logged[1][1], ngx.ERR)
    truthy(logged[1][2]:find("canary write failed", 1, true))
    -- It appears: written, the recovery logged once.
    truthy(os.execute("mkdir " .. dir))
    truthy(health.canary_tick(path, log))
    truthy(health.canary_tick(path, log))
    eq(#logged, 2, "one recovery line")
    eq(logged[2][1], ngx.WARN)
    local f = io.open(path)
    eq(f:read("*a"), health.CANARY_BODY)
    f:close()
    -- Removed (or clobbered) under a healthy node: rewritten, nothing logged.
    os.remove(path)
    truthy(health.canary_tick(path, log))
    f = io.open(path, "w")
    f:write("x")
    f:close()
    truthy(health.canary_tick(path, log))
    f = io.open(path)
    eq(f:read("*a"), health.CANARY_BODY)
    f:close()
    eq(#logged, 2)
    os.remove(path)
    os.remove(dir)
    health.reset_canary_state()
end)

test("health verdict", function()
    settings.health_max_age = 30
    truthy((health.verdict({ ready = true, at = 1000 }, 1010, true)))
    falsy((health.verdict({ ready = false, at = 1000 }, 1010, true)), "agent not ready")
    falsy((health.verdict({ ready = true, at = 1000 }, 1031, true)), "stale")
    falsy((health.verdict({ ready = true, at = 1000 }, 1010, false)), "canary")
    falsy((health.verdict(nil, 1010, true)), "no document")
end)

local function config(over)
    local c = {
        revision = 3, draining = false, fleet_wildcard = "*.cdn.hippius.com", compression = { "gzip" },
        zones = { z1 = { state = "active", serving = true, origin = { type = "s3", bucket = "media", prefix = "site/" }, settings = {} } },
        hostnames = { ["img.example.com"] = "z1", ["*.wild.example.com"] = "z1" },
        purges = { z1 = { zone_generation = 1, prefixes = {} } },
        blocks = { { kind = "path", value = "/bad.bin", zone_id = "z1" }, { kind = "prefix", value = "/secret/" } },
        acme_http01 = { tok_1 = "tok_1.thumb" },
        peers = {},
    }
    for k, v in pairs(over or {}) do c[k] = v end
    return cjson.encode(c)
end

test("config validation", function()
    local d = assert(docs.validate("config", config()))
    eq(d.hostnames["img.example.com"], "z1")
    truthy(d.blocks.exact.z1["/bad.bin"])
    eq(d.blocks.prefixes["*"][1], "/secret/")
    eq(d.acme.tok_1, "tok_1.thumb")
    -- Encoded feed paths are stored decoded; two encodings keep the max.
    local enc = assert(docs.validate("config", config({
        blocks = { { kind = "path", value = "/a%20b.txt", zone_id = "z1" } },
        purges = { z1 = { zone_generation = 2, prefixes = { ["/x%20y/"] = 3, ["/x y/"] = 5, ["/x%20y%2F"] = 4 } } },
    })))
    truthy(enc.blocks.exact.z1["/a b.txt"])
    eq(enc.purges.z1.prefixes["/x y/"], 5)
    eq(enc.purges.z1.zone_generation, 2)
    truthy(d.compression.gzip)
    local bad = {
        { hostnames = { ["Bad Host"] = "z1" } },
        { hostnames = { ["x.example.com"] = "nope" } },
        { zones = { z1 = { state = "weird", serving = true, origin = { type = "s3", bucket = "media" } } } },
        { zones = { z1 = { state = "active", serving = true, origin = { type = "http", host = "169.254.169.254" } } } },
        { zones = { z1 = { state = "active", serving = true, origin = { type = "s3", bucket = "media", prefix = "../x/" } } } },
        { acme_http01 = { tok = "other.thumb" } },
        { compression = { "zstd" } },
        { revision = "3" },
        { purges = { z1 = { zone_generation = "1" } } },
        { zones = { z1 = { state = "active", serving = true, origin = { type = "s3", bucket = "media", prefix = "site" } } } },
    }
    for i, over in ipairs(bad) do
        local ok = docs.validate("config", config(over))
        falsy(ok, "case " .. i)
    end
    -- A block or purge key that is not a request path is skipped, not
    -- fatal: one bad customer purge must not freeze the node's config.
    local odd = assert(docs.validate("config", config({
        blocks = { { kind = "prefix", value = "/no-slash" }, { kind = "path", value = "/%2e%2e/x" },
                   { kind = "regex", value = "/x" }, { kind = "path", value = "/ok" } },
        purges = { z1 = { zone_generation = 1,
            prefixes = { ["/a/../b/"] = 1, ["/a%00/"] = 2, ["/fine/"] = 3, ["/no-slash"] = 4 },
            paths = { ["/x%20y.png"] = 5, ["/a%5cb"] = 6 } } },
    })))
    eq(odd.skipped, 6)
    eq(odd.purges.z1.paths["/no-slash"], 4, "a prefixes key without its / is an exact path")
    eq(odd.purges.z1.prefixes["/no-slash"], nil)
    truthy(odd.blocks.exact["*"]["/ok"])
    eq(odd.purges.z1.prefixes["/fine/"], 3)
    eq(odd.purges.z1.paths["/x y.png"], 5)
    -- No `paths` map (older backend): empty.
    local old = assert(docs.validate("config", config({ purges = { z1 = { zone_generation = 1 } } })))
    eq(next(old.purges.z1.paths), nil)
    -- A non-serving zone may carry an origin this data plane cannot use.
    truthy(docs.validate("config", config({ zones = { z1 = { state = "active", serving = false,
        origin = { type = "http", host = "example.com" } } } })))
    falsy(docs.validate("config", "not json"))
    falsy(docs.validate("nonsense", "{}"))
end)

test("certs, secrets, health and attestation validation", function()
    truthy(docs.validate("certs", cjson.encode({ default = cjson.null, certs = {} })))
    falsy(docs.validate("certs", cjson.encode({ default = "*.x.com", certs = {} })), "default must exist")
    falsy(docs.validate("certs", cjson.encode({ certs = { a = { chain_pem = 1 } } })))
    truthy(docs.validate("secrets", cjson.encode({ zones = { z1 = { s3_credentials = "{}" } } })))
    falsy(docs.validate("secrets", cjson.encode({ zones = { z1 = { s3_credentials = 5 } } })))
    truthy(docs.validate("health", cjson.encode({ ready = true, at = 5 })))
    falsy(docs.validate("health", cjson.encode({ ready = "yes", at = 5 })))
    truthy(docs.validate("attestation", cjson.encode({ format = "f", spki_sha256_hex = "aa", report_b64 = "AA==" })))
end)

test("s3_credentials: the backend's shape, the long name, and named refusals", function()
    local function creds(t) return { s3_credentials = cjson.encode(t) } end
    -- What the backend seals (cdn/origin.py): access_key_id + secret.
    local c = assert(router.s3_credentials(creds({ access_key_id = "hip_sub_1", secret = "s3cr3t" })))
    eq(c.access_key_id, "hip_sub_1")
    eq(c.secret_access_key, "s3cr3t")
    eq(c.session_token, nil)
    c = assert(router.s3_credentials(creds({ access_key_id = "AK", secret_access_key = "S", session_token = "T" })))
    eq(c.secret_access_key, "S")
    eq(c.session_token, "T")
    c = assert(router.s3_credentials(creds({ access_key_id = "AK", secret = "S", session_token = "" })))
    eq(c.session_token, nil)
    -- Both names: the long one wins; a JSON null long name falls back.
    c = assert(router.s3_credentials(creds({ access_key_id = "AK", secret_access_key = "L", secret = "S" })))
    eq(c.secret_access_key, "L")
    c = assert(router.s3_credentials({ s3_credentials = '{"access_key_id":"AK","secret_access_key":null,"secret":"S"}' }))
    eq(c.secret_access_key, "S")
    -- A present but invalid long name is refused, not silently replaced.
    eq(select(2, router.s3_credentials(creds({ access_key_id = "AK", secret_access_key = "", secret = "S" }))),
        "secret missing or invalid")
    -- No secret at all: a public bucket.
    eq(router.s3_credentials(nil), false)
    eq(router.s3_credentials({}), false)
    -- Refusals name the field and never carry a value.
    local cases = {
        { { s3_credentials = "not json" }, "s3_credentials is not a JSON object" },
        { creds({ secret = "S" }), "access_key_id missing or invalid" },
        { creds({ access_key_id = "AK" }), "secret missing or invalid" },
        { creds({ access_key_id = "AK", secret = "a b" }), "secret missing or invalid" },
        { creds({ access_key_id = "AK", secret = "S", session_token = 5 }), "session_token invalid" },
    }
    for _, case in ipairs(cases) do
        local ok, why = router.s3_credentials(case[1])
        eq(ok, nil, case[2])
        eq(why, case[2])
    end
end)

test("s3_credentials: the backend's sealed plaintexts (shared contract vector)", function()
    local here = debug.getinfo(1, "S").source:sub(2):match("(.*/)") or "./"
    local f = assert(io.open(here .. "../../../../../test_vectors/cdn/s3_credentials.json"))
    local vectors = assert(cjson.decode(f:read("*a")))
    f:close()
    truthy(#vectors.cases >= 2)
    for _, case in ipairs(vectors.cases) do
        local c, why = router.s3_credentials({ s3_credentials = case.plaintext })
        truthy(c, case.name .. ": " .. tostring(why))
        eq(c.access_key_id, case.access_key_id, case.name)
        eq(c.secret_access_key, case.secret_access_key, case.name)
    end
end)

test("unusable-credential CRIT lines are rate-limited per zone and reason", function()
    truthy(router.should_log_credentials("zq", "secret missing or invalid", 1000))
    falsy(router.should_log_credentials("zq", "secret missing or invalid", 1030))
    truthy(router.should_log_credentials("zq", "access_key_id missing or invalid", 1030), "another reason")
    truthy(router.should_log_credentials("zp", "secret missing or invalid", 1030), "another zone")
    truthy(router.should_log_credentials("zq", "secret missing or invalid", 1060))
end)

test("router helpers", function()
    local d = assert(docs.validate("config", config()))
    eq(router.zone_for(d, "img.example.com"), "z1")
    eq(router.zone_for(d, "a.wild.example.com"), "z1")
    eq(router.zone_for(d, "a.b.wild.example.com"), nil)
    eq(router.zone_for(d, "other.example.com"), nil)
    eq(router.origin_uri({ bucket = "media", prefix = "site/" }, "/a b.txt"), "/media/site/a%20b.txt")
    eq(router.origin_uri({ bucket = "media" }, "/"), nil, "never the bucket root")
    truthy(util.valid_prefix(""), "an empty prefix is the whole bucket")
    eq(router.origin_uri({ bucket = "media", prefix = cjson.null }, "/x"), "/media/x")
end)

test("certificate selection", function()
    local store = { default = "*.cdn.hippius.com", doc = { certs = {
        ["*.cdn.hippius.com"] = {}, ["img.example.com"] = {}, ["*.example.org"] = {} } } }
    eq(cert.select(store, "img.example.com"), "img.example.com")
    eq(cert.select(store, "a.example.org"), "*.example.org")
    eq(cert.select(store, "z1.cdn.hippius.com"), "*.cdn.hippius.com")
    -- The backend's probe (SNI health.cdn.hippius.com) gets the fleet
    -- wildcard, with or without any customer hostname.
    eq(cert.select(store, "health.cdn.hippius.com"), "*.cdn.hippius.com")
    eq(cert.select(store, "unknown.test"), "*.cdn.hippius.com")
    eq(cert.select(store, nil), "*.cdn.hippius.com")
    store.default = nil
    eq(cert.select(store, "unknown.test"), nil, "no default: refuse")
end)

for _, t in ipairs(tests) do
    local ok, err = pcall(t[2])
    if ok then
        print("ok   " .. t[1])
    else
        failures = failures + 1
        print("FAIL " .. t[1] .. ": " .. tostring(err))
    end
end
print(string.format("%d tests, %d failures", #tests, failures))
if failures > 0 then
    os.exit(1)
end
