# Cloudflare DNS records for the public-facing service hostnames.
#
# ── MVP vs final design ─────────────────────────────────────────────
#
# These records are the **MVP** posture: services are reached through
# ingress-nginx on the control-plane node, fronted by Cloudflare
# (`proxied = true` → Cloudflare terminates edge TLS and hides the
# origin IP).
#
# The **locked final design** is Edge-via-NetBird: KBS / vali traffic
# flows over the NetBird mesh through the Edge opaque relay, not the
# public internet. `kbs` / `vali` here are therefore transitional — they
# exist so Milestone A (first attested VM boot) is reachable before the
# mesh is stood up, and will narrow to mesh-only once the Edge GW is
# deployed.
#
# The `edge` record (PR-H7) is separate from the proxied block below:
# it resolves to the Edge's MetalLB LoadBalancer IP — a PRIVATE address
# — and is `proxied = false` (Cloudflare cannot proxy a private origin).
# See the `cloudflare_record.edge` resource at the end.
#
# ── Placeholder IPs ─────────────────────────────────────────────────
#
# EVERY address here defaults to the RFC 5737 TEST-NET-1 range
# (`192.0.2.0/24`) — an un-filled value is then obviously a placeholder,
# never a real host. Fill the real IPs (via `terraform.tfvars`) once the
# corresponding service is deployed: kbs after PR-K6, vali after PR-K7,
# argocd once the ingress LoadBalancer has an address.
#
# Cloudflare DNS records cannot carry an arbitrary key=value tag map
# (the `tags` field is a list-of-strings, Enterprise-only) — the
# `app.kubernetes.io/part-of` + `managed-by` provenance is carried in
# the `comment` field instead.

locals {
  # Public-facing service hostnames under the zone. All are proxied:
  # the MVP fronts every one with Cloudflare.
  dns_records = {
    kbs    = { ip = var.kbs_public_ip }
    vali   = { ip = var.vali_public_ip }
    argocd = { ip = var.argocd_public_ip }
  }
}

resource "cloudflare_record" "service" {
  for_each = local.dns_records

  zone_id = var.cloudflare_zone_id
  name    = each.key
  type    = "A"
  content = each.value.ip

  # Proxied through Cloudflare — edge TLS termination + origin-IP
  # hiding for these public-facing MVP endpoints.
  proxied = true

  # Cloudflare requires ttl = 1 ("automatic") for proxied records.
  ttl = 1

  comment = "managed-by=terraform app.kubernetes.io/part-of=hippius-compute"
}

# ── Edge gateway — NetBird-mesh-internal record (PR-H7) ──────────────
#
# Unlike the proxied public records above, `edge.hippius.network`
# resolves to the Edge's MetalLB LoadBalancer IP — a PRIVATE, not
# public-routable address (`var.edge_loadbalancer_ip`). It is
# `proxied = false`: Cloudflare cannot proxy to a private origin, and
# miners do not reach the Edge over the public internet anyway — they
# join the NetBird mesh and route to the MetalLB pool range via the
# mesh subnet route (NetBird dashboard: Routes → network <LB pool CIDR>,
# routing peer = the control-plane node, distribution group `miner`).
#
# The record is a name→IP convenience for mesh-joined miners. The IP is
# private and unreachable off-mesh, so publishing it discloses only an
# internal address, never a reachable surface — and the relay is mTLS,
# so reaching the IP is not access.
resource "cloudflare_record" "edge" {
  zone_id = var.cloudflare_zone_id
  name    = "edge"
  type    = "A"
  content = var.edge_loadbalancer_ip

  # NetBird-only: a private origin cannot be Cloudflare-proxied.
  proxied = false
  ttl     = 300

  comment = "managed-by=terraform app.kubernetes.io/part-of=hippius-compute"
}
