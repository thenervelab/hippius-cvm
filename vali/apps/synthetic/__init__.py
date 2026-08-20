"""Synthetic monitor — continuous self-test of the live control plane.

Two tiers, both CronJob driven (see the `vali_synthetic_monitor`
management command):

- **light** (frequent, ~10-15 min): read-only health of the fleet — vali
  API up, KBS reachable, dispatchable == on-chain-active, host-attestor
  coverage, dynamic-capacity sane (a fabricated over-report cannot
  inflate it), no stuck launch/decommission jobs, epoch-close advancing.
- **full** (every 6 h, rotating the four distros): launch a THROWAWAY
  golden VM through the real public API, watch it boot (kek-released →
  running, NetBird IP), then decommission it via the real §24 API and
  verify crypto-erase. SELF-CLEANING — the VM is torn down on every exit
  path, so a failed run never leaks a VM.

Every result is pushed to the Prometheus Pushgateway (`apps.synthetic.
metrics`); a `PrometheusRule` alerts on `success==0` / staleness and
routes to the existing Alertmanager Slack receiver.

A light-tier check whose failure is KNOWN AND ACCEPTED can be excluded
from the tier roll-up by a named, reasoned, ≤30-day acknowledgement
(`apps.synthetic.ack`) — so one standing failure cannot pin
`hippius_synthetic_light_success` at 0 and hide every other one. The
acknowledged check still runs, still reports, still publishes its own
0, and the acknowledgement itself is alerted on (expiring / stale /
refused). Read that module's preamble before adding an entry.
"""
