# Example — ALERT: replay-attempt spike

### Situation given to the sentinel

```
### [ALERT] replay_attempts
- summary: 47 KbsError::Replay rejections in the last 10 min, vs a
  trailing baseline of 0–2 per 10 min.
- fingerprint: replay:2026-05-18T15:20
- details: {"replay_count": 47, "baseline_per_10min": 1, "window_min": 10}

### [WARN] release_anomaly
- summary: KBS denial fraction drifted from 1.2% to 6.8% over 30 min.
- fingerprint: denial-shift:2026-05-18T15
- details: {"denial_pct_before": 1.2, "denial_pct_after": 6.8}
```

### Model response

## [ALERT] Sustained ticket-replay attack against KBS
- **Rule:** replay_attempts (correlated with release_anomaly)
- **Detected:** 2026-05-18T15:20:00Z
- **Assessment:** 47 replay rejections in 10 minutes against a
  baseline near zero is not noise — something is resubmitting captured
  tickets. The concurrent denial-fraction jump (1.2% → 6.8%) is the
  same event seen from the release rule's angle: the replays are what
  is pushing denials up. KBS is correctly rejecting every one, so
  there is no integrity breach — but the source is actively probing.
- **Recommended action:** Identify the origin of the replayed tickets
  from the KBS audit tail and the NetBird peer list; if it is a single
  peer, have an operator revoke its access. Confirm the §22 allowlist
  epoch has not also moved.
- **Confidence:** high

### Why this is the right call

Two findings, one incident — the senior SRE collapses them into a
single ALERT rather than reporting them separately. It is ALERT, not
CRITICAL: KBS is rejecting the replays, so integrity holds and no page
is warranted — but it is a real attack needing a same-day operator
response, which is exactly the ALERT rung.
