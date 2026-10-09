-- Sanity check of geoip.lua against the real, pinned DB-IP database
-- (fetch-geoip.sh output), run by tests/run.sh when HIPPIUS_REAL_GEOIP_DB
-- is set (the cdn-dataplane workflow fetches it). Well-known anycast and
-- hosting addresses only: their country is stable from month to month.
local geoip = require("hippius_cdn.geoip")
local path = assert(os.getenv("HIPPIUS_REAL_GEOIP_DB"))
local ok, info = geoip.load(path)
assert(ok, info)
print("     " .. info)
local cases = {
    { "8.8.8.8", "US" },
    { "10.0.0.1", "XX" }, { "100.64.1.1", "XX" },
}
for _, c in ipairs(cases) do
    local got = geoip.country(c[1])
    assert(got == c[2], c[1] .. ": expected " .. c[2] .. ", got " .. got)
end
-- Anycast addresses resolve to some country (which may move between months).
for _, a in ipairs({ "1.1.1.1", "2001:4860:4860::8888" }) do
    local r = geoip.country(a)
    assert(r:match("^[A-Z][A-Z]$") and r ~= "XX", a .. ": " .. r)
end
local seen = 0
for i = 1, 254 do
    local r = geoip.country(i .. ".10.20.30")
    assert(r == "XX" or r:match("^[A-Z][A-Z]$"), r)
    if r ~= "XX" then seen = seen + 1 end
end
assert(seen > 150, "too few addresses resolve: " .. seen)
print("     real database: " .. seen .. "/254 sampled /8s resolve to a country")
