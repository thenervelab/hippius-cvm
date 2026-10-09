-- Lua unit tests, run with the OpenResty `resty` CLI:
--   resty -I packer/cdn-node/openresty/lua packer/cdn-node/openresty/tests/unit/run.lua
-- A minimal harness: each test is a function; any error fails the run.
local util = require("hippius_cdn.util")
local sigv4 = require("hippius_cdn.sigv4")
local meter = require("hippius_cdn.meter")
local health = require("hippius_cdn.health")
local docs = require("hippius_cdn.docs")
local router = require("hippius_cdn.router")
local rules = require("hippius_cdn.rules")
local limits = require("hippius_cdn.limits")
local geoip = require("hippius_cdn.geoip")
local mime = require("hippius_cdn.mime")
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

test("meter passes every nginx cache status to the agent", function()
    -- The agent counts hit / stale / updating / revalidated as hits and
    -- miss / expired / bypass as misses (usage report `cache`).
    local want = { HIT = "hit", STALE = "stale", UPDATING = "updating", REVALIDATED = "revalidated",
        MISS = "miss", EXPIRED = "expired", BYPASS = "bypass" }
    for nginx, agent in pairs(want) do
        local r = meter.record({ zone = "z1", billable = true }, { upstream_cache_status = nginx, bytes_sent = "1" }, 200)
        eq(r.cache, agent, nginx)
    end
    eq(meter.record({}, { bytes_sent = "1" }, 421).cache, nil, "no cache status")
    eq(meter.record({}, { upstream_cache_status = "WEIRD", bytes_sent = "1" }, 200).cache, nil)
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

test("content-type fallback by extension, never to a script-capable type", function()
    local prefix = os.getenv("OPENRESTY_PREFIX") or "/opt/openresty"
    mime.load(prefix .. "/nginx/conf/mime.types")
    local cases = {
        { "/a.css", nil, "text/css" },
        { "/a.js", nil, "application/javascript" },
        { "/a.png", "application/octet-stream", "image/png" },
        { "/a.JSON", "binary/octet-stream", "application/json" },
        { "/a.txt", "", "text/plain" },
        -- Script-capable under *.cdn.hippius.com: never guessed.
        { "/cdn-test.html", nil, "application/octet-stream" },
        { "/logo.svg", "binary/octet-stream", "application/octet-stream" },
        { "/a.xhtml", nil, "application/octet-stream" },
        { "/feed.xml", nil, "application/octet-stream" },
        -- Unknown or no extension.
        { "/a.unknownext", nil, "application/octet-stream" },
        { "/README", "binary/octet-stream", "application/octet-stream" },
    }
    for _, c in ipairs(cases) do
        eq(mime.fallback(c[1], c[2]), c[3], c[1] .. " / " .. tostring(c[2]))
    end
    -- A parameter on a generic declared type does not stop the fallback.
    eq(mime.fallback("/a.css", "Application/Octet-Stream; charset=utf-8"), "text/css")
    eq(mime.fallback("/a.css", "  "), "text/css")
    -- Only allowlisted families come out of the fallback.
    truthy(mime.fallback_allowed("image/png"))
    truthy(mime.fallback_allowed("font/woff2"))
    falsy(mime.fallback_allowed("image/svg+xml"))
    falsy(mime.fallback_allowed("text/mathml"))
    falsy(mime.fallback_allowed("application/pdf"))
    eq(mime.fallback("/a.pdf", nil), "application/octet-stream")
    -- Entries spanning two lines in mime.types are parsed.
    local parsed = mime.parse("types {\n    text/css css;\n    application/vnd.example.long\n        pptx docx;\n}\n")
    eq(parsed.pptx, "application/vnd.example.long")
    eq(parsed.docx, "application/vnd.example.long")
    eq(parsed.css, "text/css")
    -- A declared type is kept, HTML included (the origin's choice).
    eq(mime.fallback("/cdn-test.html", "text/html; charset=utf-8"), nil)
    eq(mime.fallback("/a.bin", "image/png"), nil)
    for _, t in ipairs({ "text/html", "text/html; charset=utf-8", "application/xhtml+xml",
        "image/svg+xml", "text/xml", "application/xml", "text/xsl", "text/mathml" }) do
        eq(mime.csp_for(t), "sandbox allow-scripts", t)
    end
    for _, t in ipairs({ "text/css", "application/javascript", "image/png", "application/json",
        "text/plain", "application/octet-stream" }) do
        eq(mime.csp_for(t), nil, t)
    end
    eq(mime.csp_for(nil), nil)
    -- Only the fleet's own names are sandboxed; custom domains are not.
    local store = { doc = { fleet_wildcard = "*.c.hipcdn.net" } }
    truthy(router.on_fleet_domain("zabc.c.hipcdn.net", store))
    falsy(router.on_fleet_domain("www.example.com", store))
    falsy(router.on_fleet_domain("a.zabc.c.hipcdn.net", store))
    falsy(router.on_fleet_domain("zabc.c.hipcdn.net", nil))
    truthy(mime.script_capable("image/svg+xml"))
    truthy(mime.script_capable("Text/HTML"))
    falsy(mime.script_capable("text/css"))
end)

test("origin header allowlist", function()
    -- The headers the S3 gateway sent on a private object in production.
    local origin = {
        ["Content-Type"] = "text/html", ["Content-Length"] = "10", ["ETag"] = '"e"',
        ["Last-Modified"] = "x", ["Accept-Ranges"] = "bytes", ["Content-Disposition"] = "inline",
        ["Cache-Control"] = "private, no-store", ["Expires"] = "0", ["Vary"] = "Origin",
        ["Server"] = "gw", ["Set-Cookie"] = "a=1", ["Location"] = "https://elsewhere.example/",
        ["x-hippius-source"] = "s", ["x-hippius-api-time-ms"] = "3", ["x-hippius-ray-id"] = "r",
        ["x-hippius-body-blake3"] = "b", ["x-hippius-body-blake3-chunk"] = "c",
        ["x-amz-meta-original-name"] = "n", ["x-amz-request-id"] = "q", ["x-amz-id-2"] = "i",
        ["Age"] = "5000",
    }
    local dropped = {}
    for _, n in ipairs(router.headers_to_drop(origin, false)) do dropped[n] = true end
    for _, keep in ipairs({ "Content-Type", "Content-Length", "ETag", "Last-Modified",
        "Accept-Ranges", "Content-Disposition" }) do
        falsy(dropped[keep], keep .. " must be kept")
    end
    for _, gone in ipairs({ "Cache-Control", "Expires", "Vary", "Server", "Set-Cookie", "Location",
        "x-hippius-source", "x-hippius-api-time-ms", "x-hippius-ray-id", "x-hippius-body-blake3",
        "x-hippius-body-blake3-chunk", "x-amz-meta-original-name", "x-amz-request-id", "x-amz-id-2",
        "Age" }) do
        truthy(dropped[gone], gone .. " must be dropped")
    end
    -- The node's own redirect keeps its Location.
    local own = {}
    for _, n in ipairs(router.headers_to_drop({ Location = "https://a/" }, true)) do own[n] = true end
    falsy(own.Location)
end)

test("geoip: countries at every record size, XX for the rest", function()
    local dir = assert(os.getenv("HIPPIUS_TEST_GEOIP_DIR"), "run through tests/run.sh")
    local cases = {
        { "2.16.0.1", "FR" }, { "2.23.255.255", "FR" }, { "2.24.0.0", "XX" },
        { "1.2.3.4", "AU" }, { "9.9.1.1", "NL" },
        { "8.8.8.8", "XX" },   -- ZZ
        { "7.7.7.7", "XX" },   -- not alpha-2
        { "6.6.6.6", "XX" },   -- no country
        { "5.5.5.5", "XX" },   -- no entry
        { "2a01::5", "DE" }, { "2A01:0:0:0:0:0:0:5", "DE" }, { "::ffff:1.2.3.4", "AU" },
        -- Private, CGNAT (the overlay), loopback: XX though the DB has them.
        { "10.1.2.3", "XX" }, { "100.64.0.9", "XX" }, { "192.168.1.1", "XX" },
        { "127.0.0.1", "XX" }, { "::1", "XX" }, { "fe80::1", "XX" }, { "::ffff:10.0.0.1", "XX" },
        -- Not addresses.
        { "", "XX" }, { "not-an-ip", "XX" }, { "1.2.3", "XX" }, { "256.1.1.1", "XX" },
        { "1:2:3", "XX" }, { "1::2::3", "XX" }, { "unix:", "XX" }, { "1.2::3", "XX" },
        { "fe80::1%eth0", "XX" },
        -- IPv4-compatible ::a.b.c.d: the IPv4 path, its private filter too.
        { "::1.2.3.4", "AU" }, { "::10.0.0.1", "XX" },
    }
    for _, rs in ipairs({ 24, 28, 32 }) do
        local ok, info = geoip.load(dir .. "/geo-" .. rs .. ".mmdb")
        truthy(ok, info)
        truthy(info:find("DBIP-Country-Lite", 1, true), info)
        for _, c in ipairs(cases) do
            eq(geoip.country(c[1]), c[2], rs .. " " .. c[1])
        end
    end
    eq(geoip.country(nil), "XX")
end)

test("geoip: a missing or corrupt database answers XX, never an error", function()
    local dir = assert(os.getenv("HIPPIUS_TEST_GEOIP_DIR"))
    for _, name in ipairs({ "truncated.mmdb", "garbage.mmdb", "badtree.mmdb", "absent.mmdb",
        "fanout.mmdb", "." }) do
        local ok, why = geoip.load(dir .. "/" .. name)
        eq(ok, nil, name)
        truthy(type(why) == "string", name)
        falsy(geoip.loaded(), name)
        eq(geoip.country("2.16.0.1"), "XX", name)
    end
end)

test("geoip: fan-out metadata is refused fast", function()
    local dir = assert(os.getenv("HIPPIUS_TEST_GEOIP_DIR"))
    local t0 = os.clock()
    local ok, why = geoip.load(dir .. "/fanout.mmdb")
    eq(ok, nil)
    truthy(why:find("metadata", 1, true), why)
    truthy(os.clock() - t0 < 1, "took " .. (os.clock() - t0) .. " s")
end)

test("geoip: hundreds of corrupted databases give XX, never an error", function()
    local dir = assert(os.getenv("HIPPIUS_TEST_GEOIP_DIR"))
    local bases = {}
    for _, rs in ipairs({ 24, 28, 32 }) do
        local f = assert(io.open(dir .. "/geo-" .. rs .. ".mmdb", "rb"))
        bases[#bases + 1] = f:read("*a")
        f:close()
    end
    local addrs = { "2.16.0.1", "1.2.3.4", "9.9.1.1", "8.8.8.8", "5.5.5.5", "2a01::5",
        "::ffff:1.2.3.4", "200.1.2.3", "2001:db8::1", "ffff::1" }
    math.randomseed(1517)
    local function pos(len)
        local k = math.random(3)
        if k == 1 then return math.random(1, math.min(len, 512)) end      -- the tree
        if k == 2 then return math.random(math.max(1, len - 2048), len) end -- records, metadata
        return math.random(1, len)
    end
    local loaded, t0 = 0, os.clock()
    for i = 1, 400 do
        local buf = bases[(i % 3) + 1]
        local kind = math.random(4)
        if kind <= 2 then
            -- 1 to 8 random bytes overwritten.
            for _ = 1, math.random(8) do
                local at = pos(#buf)
                buf = buf:sub(1, at - 1) .. string.char(math.random(0, 255)) .. buf:sub(at + 1)
            end
        elseif kind == 3 then
            buf = buf:sub(1, math.random(0, #buf - 1))                      -- truncated
        else
            local at = pos(#buf)                                             -- bytes inserted
            local junk = {}
            for j = 1, math.random(1, 16) do junk[j] = string.char(math.random(0, 255)) end
            buf = buf:sub(1, at) .. table.concat(junk) .. buf:sub(at + 1)
        end
        -- Checked mode: every byte read is verified, so a read the code did
        -- not bound first is counted instead of reading past the buffer.
        local ok, info = geoip.load_bytes(buf, true)
        truthy(ok == true or (ok == nil and type(info) == "string"), "load result " .. tostring(info))
        if ok then loaded = loaded + 1 end
        for _, a in ipairs(addrs) do
            local r = geoip.country(a)
            truthy(r == "XX" or r:match("^[A-Z][A-Z]$"), a .. " -> " .. tostring(r))
        end
    end
    -- Reads can only run off the end while decoding the metadata (it is
    -- last): cut every base at every byte after the marker, and flip bytes
    -- inside the metadata only.
    local cuts, flips = 0, 0
    for _, base in ipairs(bases) do
        local m = base:find("\171\205\239MaxMind.com", 1, true)
        for cut = m, #base - 1 do
            local ok = geoip.load_bytes(base:sub(1, cut), true)
            truthy(ok == nil or ok == true)
            cuts = cuts + 1
        end
        for _ = 1, 100 do
            local buf = base
            for _ = 1, math.random(3) do
                local at = math.random(m + 14, #buf)
                buf = buf:sub(1, at - 1) .. string.char(math.random(0, 255)) .. buf:sub(at + 1)
            end
            if geoip.load_bytes(buf, true) then
                truthy(geoip.country("2.16.0.1"):match("^[A-Z][A-Z]$"))
            end
            flips = flips + 1
        end
    end
    print(string.format("     geoip fuzz: 400 corrupted databases (%d still loadable), %d metadata cuts, "
        .. "%d metadata flips in %.1f s", loaded, cuts, flips, os.clock() - t0))
    eq(geoip.unchecked_reads, 0, "a read went past the buffer without a bounds check")
    truthy(os.clock() - t0 < 60, "fuzz too slow")
end)

test("geoip: every multi-byte form cut one byte short is refused, no read past the end", function()
    local M = "\171\205\239MaxMind.com"
    -- Metadata made of a single value whose encoding stops one byte early.
    local cases = {
        { "\93", "string, size 29: missing size byte" },
        { "\94\0", "string, size 30: 1 of 2 size bytes" },
        { "\95\0\0", "string, size 31: 2 of 3 size bytes" },
        { "\0", "extended type: missing type byte" },
        { "\32", "pointer ss=0: missing byte" },
        { "\40\0", "pointer ss=1: 1 of 2 bytes" },
        { "\48\0\0", "pointer ss=2: 2 of 3 bytes" },
        { "\56\0\0\0", "pointer ss=3: 3 of 4 bytes" },
        { "\196\1\2\3", "uint32: 3 of 4 bytes" },
        { "\0\2\1", "uint64: 1 of 2 bytes" },
        { "\66a", "string: 1 of 2 bytes" },
        { "\225\66ab", "map: key without a value" },
    }
    for _, c in ipairs(cases) do
        local before = geoip.unchecked_reads
        local ok, why = geoip.load_bytes(M .. c[1], true)
        eq(ok, nil, c[2])
        truthy(type(why) == "string", c[2])
        eq(geoip.unchecked_reads, before, c[2] .. ": read past the end")
    end
end)

test("geoip: lookup cost", function()
    local dir = assert(os.getenv("HIPPIUS_TEST_GEOIP_DIR"))
    assert(geoip.load(dir .. "/geo-24.mmdb"))
    local addrs = { "2.16.0.1", "1.2.3.4", "5.5.5.5", "2a01::5", "9.9.1.1", "10.1.2.3" }
    local n, t0 = 0, os.clock()
    for _ = 1, 50000 do
        for i = 1, #addrs do
            geoip.country(addrs[i])
            n = n + 1
        end
    end
    local us = (os.clock() - t0) * 1e6 / n
    print(string.format("     geoip: %.2f us per lookup (%d lookups)", us, n))
    truthy(us < 50, "lookup too slow: " .. us .. " us")
end)

test("cache rules: compile, drop the unusable, first match wins whole (contract C.4)", function()
    local raw = {
        { match = { path_prefix = "/static/" }, actions = { edge_ttl = 86400, browser_ttl = 3600 } },
        { match = { glob = "*.jpg" }, actions = { edge_ttl = 60, query_string = "include" } },
        { match = { glob = "/img/*.png" }, actions = { edge_ttl = 61 } },
        { match = { glob = "/deep/**.png" }, actions = { edge_ttl = 62 } },
        { match = { glob = "/a+b/(x)?.txt" }, actions = { edge_ttl = 63 } },
        { match = { path_prefix = "/my%20dir/" }, actions = { edge_ttl = 64 } },
        { match = { glob = "/sp%20ace/*" }, actions = { edge_ttl = 65 } },
        { match = { extensions = { ".MP4", "webm" } }, actions = { bypass = true } },
        { match = { path_prefix = "/" }, actions = { edge_ttl = "origin", browser_ttl = cjson.null } },
        -- Unusable, dropped:
        { match = { regex = ".*" }, actions = { edge_ttl = 1 } },
        { match = { path_prefix = "/x/", glob = "*" }, actions = { edge_ttl = 1 } },
        { match = { path_prefix = "nope" }, actions = { edge_ttl = 1 } },
        { match = { path_prefix = "/a b/" }, actions = { edge_ttl = 1 } },
        { match = { path_prefix = "/50%/" }, actions = { edge_ttl = 1 } },
        { match = { path_prefix = "/x/" }, actions = { edge_ttl = -1 } },
        { match = { path_prefix = "/x/" }, actions = { edge_ttl = 365 * 86400 + 1 } },
        { match = { path_prefix = "/x/" }, actions = { edge_ttl = 1.5 } },
        { match = { path_prefix = "/x/" }, actions = { teleport = true } },
        { match = { path_prefix = "/x/" }, actions = { bypass = "yes" } },
        { match = { path_prefix = "/x/" }, actions = {} },
        { match = { glob = "a***b" }, actions = { edge_ttl = 1 } },
        { match = { glob = "img/*.png" }, actions = { edge_ttl = 1 } },
        { match = { glob = string.rep("a", 257) }, actions = { edge_ttl = 1 } },
        { match = { extensions = { "a.b" } }, actions = { edge_ttl = 1 } },
        "not a rule",
    }
    local compiled, dropped = rules.compile(raw)
    eq(#compiled, 9); eq(dropped, 16)
    local function rule(path)
        local r = rules.match(compiled, path)
        return r and r.actions
    end
    -- First match wins whole: /static/x.jpg gets rule 1's actions only
    -- (no query_string from the jpg rule).
    eq(rule("/static/x.jpg").edge, 86400)
    eq(rule("/static/x.jpg").qs, nil)
    eq(rule("/a/b/photo.jpg").edge, 60, "a glob without / matches the file name")
    eq(rule("/a/b/photo.jpeg").edge, "origin")
    eq(rule("/a/b/photo.JPG").edge, "origin", "globs are case-sensitive")
    eq(rule("/img/a.png").edge, 61)
    eq(rule("/img/sub/a.png").edge, "origin", "* stays within a segment")
    eq(rule("/deep/a.png").edge, 62)
    eq(rule("/deep/x/y/z.png").edge, 62, "** crosses segments")
    eq(rule("/a+b/(x)1.txt").edge, 63, "pattern characters are literal")
    eq(rule("/a+b/(x)/.txt").edge, "origin", "? is not /")
    eq(rule("/my dir/f").edge, 64, "a path_prefix is decoded once")
    eq(rule("/sp ace/f").edge, 65, "so is a glob")
    eq(rule("/v/CLIP.Mp4").bypass, true, "extensions are case-insensitive")
    eq(rule("/v.mp4/clip").bypass, nil, "only the last segment counts")
    eq(rule("/anything").browser, nil, "null browser_ttl: the default")
    eq(rules.match({}, "/x"), nil)
    eq(rules.match(nil, "/x"), nil)
    eq(select(2, rules.compile(nil)), 0)
    eq(select(2, rules.compile("rules")), 1)
    eq(rules.last_extension("/a/b.TAR.GZ"), "gz")
    eq(rules.last_extension("/a.b/c"), nil)
end)

test("cache rules: the largest valid zone keeps every glob", function()
    -- 8 globs of 256 bytes: the per-zone cap, exactly.
    local raw = {}
    for k = 1, 8 do
        raw[k] = { match = { glob = "/" .. string.rep("ab", 127) .. "?" }, actions = { edge_ttl = k } }
    end
    local compiled, dropped = rules.compile(raw)
    eq(#compiled, 8); eq(dropped, 0)
    -- And it stays bounded: maximal globs, none matching, on a 4 KiB path.
    local long = "/" .. string.rep("a", 4094)
    local t0 = os.clock()
    eq(rules.match(compiled, long), nil)
    local spent = os.clock() - t0
    print(string.format("     glob: the cap in maximal globs on a 4 KiB path in %.1f ms", spent * 1000))
    truthy(spent < 0.1, "took " .. spent .. " s")
end)

test("cache rules: the glob matcher agrees with a reference, in bounded time", function()
    -- Reference (contract C.4): `*` any run without "/", `**` any run,
    -- `?` one character but "/"; memoised recursion.
    local function ref(g, s)
        if not g:find("/", 1, true) then
            s = s:match("([^/]*)$")
        end
        local memo = {}
        local function go(i, j)
            local key = i * 8192 + j
            if memo[key] ~= nil then return memo[key] end
            local r
            if i > #g then
                r = j > #s
            elseif g:sub(i, i + 1) == "**" then
                r = go(i + 2, j) or (j <= #s and go(i, j + 1))
            elseif g:sub(i, i) == "*" then
                r = go(i + 1, j) or (j <= #s and s:sub(j, j) ~= "/" and go(i, j + 1))
            elseif j > #s then
                r = false
            elseif g:sub(i, i) == "?" then
                r = s:sub(j, j) ~= "/" and go(i + 1, j + 1)
            else
                r = g:sub(i, i) == s:sub(j, j) and go(i + 1, j + 1)
            end
            memo[key] = r
            return r
        end
        return go(1, 1)
    end
    math.randomseed(1527)
    local alpha = { "a", "b", "/" }
    local function rand_path(n)
        local t = { "/" }
        for k = 1, n do t[#t + 1] = alpha[math.random(#alpha)] end
        return table.concat(t)
    end
    local function rand_glob(n, slash)
        local t = slash and { "/" } or {}
        local set = slash and { "a", "b", "/", "*", "**", "?" } or { "a", "b", "*", "**", "?" }
        for k = 1, n do t[#t + 1] = set[math.random(#set)] end
        return table.concat(t)
    end
    local tried = 0
    for _ = 1, 4000 do
        local g = rand_glob(math.random(1, 7), math.random(2) == 1)
        local gl = rules.compile_glob(g)
        if gl then -- "***" from adjacent stars is refused
            local path = rand_path(math.random(0, 12))
            eq(rules.glob_match(gl, path), ref(g, path), g .. " vs " .. path)
            tried = tried + 1
        end
    end
    truthy(tried > 2500, "too few usable random globs: " .. tried)
    for _ = 1, 300 do -- patterns over one 32-bit word
        local g = rand_glob(math.random(30, 60), true)
        local gl = rules.compile_glob(g)
        if gl then
            local path = rand_path(math.random(20, 90))
            eq(rules.glob_match(gl, path), ref(g, path), g .. " vs " .. path)
        end
    end
    -- The worst inputs for a backtracking matcher (a zone owner writes the
    -- glob, any client picks the path): bounded by target x pattern words.
    local long = "/" .. string.rep("a", 4094)
    local deep = "/" .. string.rep("a/", 2046) .. "a"
    local t0 = os.clock()
    for _, case in ipairs({
        { "*a*a*a*a*a*a*a*b", long }, { "/**a**a**a**b", long }, { "/**a**a**a**b", deep },
        { "*?" .. string.rep("a", 240) .. "b*", long }, { "/" .. string.rep("**a", 80) .. "b", deep },
    }) do
        falsy(rules.glob_match(rules.compile_glob(case[1]), case[2]), case[1])
    end
    local spent = os.clock() - t0
    print(string.format("     glob: 5 worst-case globs on 4 KiB paths in %.1f ms", spent * 1000))
    truthy(spent < 0.2, "glob matching took " .. spent .. " s")
end)

test("cache rules: decisions and the query key", function()
    local d = rules.decide(nil)
    eq(d.edge, "default"); eq(d.bypass, false); eq(d.skip_lookup, false); eq(d.browser, nil)
    eq(rules.edge_header(d), "default")
    d = rules.decide({ actions = { edge = 0 } })
    eq(d.skip_lookup, true); eq(d.bypass, false, "edge 0 still stores a 404"); eq(rules.edge_header(d), "0")
    d = rules.decide({ actions = { bypass = true, edge = 600 } })
    eq(d.skip_lookup, true); eq(d.bypass, true)
    d = rules.decide({ actions = { edge = 600, browser = 30 } })
    eq(rules.edge_header(d), "600"); eq(d.browser, 30)
    d = rules.decide({ actions = { edge = "origin" } })
    eq(rules.edge_header(d), "origin")

    eq(rules.query_key("ignore", "b=2&a=1"), "")
    eq(rules.query_key("include", "b=2&a=1&a=0"), "a=0&a=1&b=2")
    eq(rules.query_key("include", "y&x=1=2&&"), "=&=&x=1=2&y=")
    eq(rules.query_key("include", "a=%41&a=A&b=+"), "a=%41&a=A&b=+", "never decoded")
    eq(rules.query_key({ whitelist = { v = true } }, "x=1&v=3&V=4&v"), "v=&v=3", "case-sensitive names")
    eq(rules.query_key({ whitelist = { v = true } }, "x=1"), "")
    eq(rules.query_key("include", nil), "")
end)

test("cache rules: the gateway's blanket header, and client headers by origin kind", function()
    for _, v in ipairs({ "private, no-store", "no-store, private", "Private,No-Store", "  private ,  no-store  " }) do
        truthy(rules.is_gateway_blanket(v), v)
    end
    for _, v in ipairs({ "private", "no-store", "private, no-store, max-age=5", "private, no-cache",
        "public, no-store", "", "no-store, no-store" }) do
        falsy(rules.is_gateway_blanket(v), v)
    end
    -- The three cases the contract owner named.
    eq(rules.origin_ttl("private, no-store", nil, 1), nil, "gateway blanket: the default hour")
    eq(rules.origin_ttl("max-age=600", nil, 1), 600, "customer max-age")
    eq(rules.origin_ttl("no-store", nil, 1), 0, "customer no-store: not cached")
    eq(rules.origin_ttl("no-store, private", nil, 1), nil, "either order")

    -- Authorization / cookie: cached for S3, bypass for any other origin.
    local s3, http = { type = "s3" }, { type = "http" }
    falsy(router.client_headers_bypass(s3, { http_cookie = "a=1" }))
    falsy(router.client_headers_bypass(s3, { http_authorization = "Basic x" }))
    truthy(router.client_headers_bypass(http, { http_cookie = "a=1" }))
    truthy(router.client_headers_bypass(http, { http_authorization = "Basic x" }))
    falsy(router.client_headers_bypass(http, {}))
end)

test("cache rules: the per-zone glob cap, at 2048 bytes and at 2049", function()
    -- Globs of `unit` (a wire form) totalling `n` bytes, 256 or fewer each,
    -- between a prefix and an extensions rule.
    local function zone(n, unit)
        local raw = { { match = { path_prefix = "/p/" }, actions = { edge_ttl = 1 } } }
        while n > 0 do
            local len = math.min(n, 256 - 256 % #unit)
            raw[#raw + 1] = { match = { glob = string.rep(unit, len / #unit) }, actions = { edge_ttl = 2 } }
            n = n - len
        end
        raw[#raw + 1] = { match = { extensions = { "jpg" } }, actions = { edge_ttl = 3 } }
        return raw
    end
    local name = "/x/" .. string.rep("a", 256)
    local compiled, dropped, over = rules.compile(zone(2048, "a"))
    eq(#compiled, 10); eq(dropped, 0); falsy(over, "2048 is within the cap")
    eq(rules.match(compiled, name).actions.edge, 2)
    compiled, dropped, over = rules.compile(zone(2049, "a"))
    truthy(over, "2049 is over the cap"); eq(dropped, 9); eq(#compiled, 2)
    -- Every glob rule is ignored; the prefix and extensions rules still apply.
    eq(rules.match(compiled, name), nil)
    eq(rules.match(compiled, "/p/a").actions.edge, 1)
    eq(rules.match(compiled, "/x/a.jpg").actions.edge, 3)
    -- The wire form counts, not the decoded pattern: "%61" is 3 bytes.
    falsy(select(3, rules.compile(zone(2046, "%61"))))
    truthy(select(3, rules.compile(zone(2049, "%61"))))
end)

test("cache rules: adversarial globs up to the cap on a long path stay within budget", function()
    -- Leading `**` keeps the state alive over the whole path; none matches.
    -- The work is per glob more than per byte, so the worst zone within
    -- the cap is the most globs: 50 rules of 40 bytes (2000 bytes).
    local raw = {}
    for k = 1, 50 do
        raw[k] = { match = { glob = "/**" .. string.rep("a", 36) .. "b" }, actions = { edge_ttl = k } }
    end
    local compiled, dropped = rules.compile(raw)
    eq(#compiled, 50); eq(dropped, 0)
    local deep = "/" .. string.rep("a/", 2046) .. "a"
    local t0 = os.clock()
    for _ = 1, 3 do
        eq(rules.match(compiled, deep), nil)
    end
    local per_request = (os.clock() - t0) / 3
    print(string.format("     glob: adversarial rules up to the cap on a 4 KiB path: %.1f ms a request", per_request * 1000))
    -- About 13 ms measured; the budget leaves room for a loaded CI runner.
    truthy(per_request < 0.2, "over the 200 ms budget: " .. per_request .. " s")
end)

test("cache rules: origin TTL", function()
    local now = 1000000000
    eq(rules.origin_ttl("private, no-store", nil, now), nil, "the S3 gateway's blanket header is no header")
    eq(rules.origin_ttl("Private,No-Store", nil, now), nil)
    eq(rules.origin_ttl("private", nil, now), 0, "any other value is honoured")
    eq(rules.origin_ttl("no-store", nil, now), 0)
    eq(rules.origin_ttl("no-cache", nil, now), 0)
    eq(rules.origin_ttl("public, max-age=120", nil, now), 120)
    eq(rules.origin_ttl("max-age=10, s-maxage=50", nil, now), 50)
    eq(rules.origin_ttl("max-age=99999999999", nil, now), rules.MAX_TTL)
    eq(rules.origin_ttl("public", nil, now), nil, "nothing usable")
    eq(rules.origin_ttl(nil, nil, now), nil)
    eq(rules.origin_ttl(nil, ngx.http_time(now + 90), now), 90)
    eq(rules.origin_ttl("private, no-store", ngx.http_time(now + 90), now), 90)
    eq(rules.origin_ttl(nil, ngx.http_time(now - 90), now), 0)
    eq(rules.origin_ttl(nil, "0", now), 0, "an invalid Expires is expired")
    eq(rules.origin_ttl("x-private-thing, max-age=5", nil, now), 5, "a word must match whole")
end)

test("cache rules: client Cache-Control and the internal TTL header", function()
    settings.default_ttl = 3600
    eq(router.client_cache_control(nil, nil), "public, max-age=3600")
    eq(router.client_cache_control(nil, 120), "public, max-age=120", "the stored edge TTL")
    eq(router.client_cache_control(nil, 0), "no-store", "the origin forbade caching")
    eq(router.client_cache_control({ skip_lookup = true }, 120), "no-store")
    eq(router.client_cache_control({ skip_lookup = true, browser = 60 }, 0), "public, max-age=60",
        "an explicit browser_ttl wins")
    eq(router.client_cache_control({ browser = 600 }, 120), "public, max-age=600")
    eq(router.client_cache_control({ browser = 0 }, 120), "public, max-age=0")

    eq(router.origin_ttl_header("default", 200), 3600)
    eq(router.origin_ttl_header("300", 206), 300)
    eq(router.origin_ttl_header("300", 304), 300)
    eq(router.origin_ttl_header("300", 404), nil, "a 404 keeps its own minute")
    eq(router.origin_ttl_header("300", 500), nil)
    eq(router.origin_ttl_header("0", 200), 0)
    eq(router.origin_ttl_header("origin", 200, "private, no-store", nil, 1), 3600,
        "the S3 gateway's blanket header: the default")
    eq(router.origin_ttl_header("origin", 200, "no-store", nil, 1), 0)
    eq(router.origin_ttl_header("origin", 200, "max-age=42", nil, 1), 42)
    eq(router.origin_ttl_header("origin", 200, nil, nil, 1), 3600, "origin silent: the default")
    eq(router.origin_ttl_header("-5", 200), 3600, "garbage: the default")
    eq(router.origin_ttl_header("1.5", 200), 3600)
end)

test("zone limits: defaults, values, refusals per second", function()
    local l, ok = limits.of({})
    eq(l.mbps, 2000); eq(l.rps, 20000); truthy(ok)
    l, ok = limits.of({ limits = { max_mbps = 10, max_rps = 0 } })
    eq(l.mbps, 10); eq(l.rps, 0); truthy(ok)
    l = limits.of({ limits = { max_rps = 5 } })
    eq(l.mbps, 2000, "a missing ceiling takes its default"); eq(l.rps, 5)
    for _, bad in ipairs({ { max_rps = -1 }, { max_mbps = 1.5 }, { max_rps = "9" }, "x" }) do
        l, ok = limits.of({ limits = bad })
        falsy(ok); eq(l.rps, 20000); eq(l.mbps, 2000)
    end
    -- A fake shared dict.
    local function dict()
        local t = {}
        return {
            get = function(_, k) return t[k] end,
            incr = function(_, k, v, init) t[k] = (t[k] or init or 0) + v; return t[k] end,
        }
    end
    local d = dict()
    eq(select(2, limits.admit(d, "z", { rps = 0, mbps = 10 }, 100)), "rps", "0: no allowance")
    eq(select(2, limits.admit(d, "z", { rps = 10, mbps = 0 }, 100)), "mbps", "0: no allowance")
    d = dict()
    local lim = { rps = 3, mbps = 1 }
    for _ = 1, 3 do truthy((limits.admit(d, "z", lim, 100))) end
    eq(select(2, limits.admit(d, "z", lim, 100)), "rps", "the 4th request of the second")
    truthy((limits.admit(d, "z", lim, 101)), "a new second")
    truthy((limits.admit(d, "other", lim, 100)), "per zone")
    -- 1 Mbit/s = 125000 bytes/s: over it in this or the previous second.
    d = dict()
    limits.account(d, "z", 125001, 200)
    eq(select(2, limits.admit(d, "z", { rps = 100, mbps = 1 }, 200)), "mbps")
    eq(select(2, limits.admit(d, "z", { rps = 100, mbps = 1 }, 201)), "mbps", "the previous second")
    truthy((limits.admit(d, "z", { rps = 100, mbps = 1 }, 202)), "two seconds later")
    limits.account(d, "z", 0, 202)
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
