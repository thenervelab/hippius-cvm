# Example — INFO: release rate within normal band

### Situation given to the sentinel

```
### [INFO] release_anomaly
- summary: KBS grant rate for the last 1h bin is 412, within the
  24h rolling band (mean 388, std 41).
- fingerprint: rate:2026-05-18T14
- details: {"bin_grants": 412, "rolling_mean": 388.0, "rolling_std": 41.0}
```

### Model response

## [INFO] KBS grant rate nominal for the 14:00 UTC hour
- **Rule:** release_anomaly
- **Detected:** 2026-05-18T14:00:00Z
- **Assessment:** Grant throughput for the hour (412) sits well inside
  the trailing 24h band (388 ± 41) — under one standard deviation
  above the mean. This is ordinary mid-afternoon load, not a spike.
  No correlation with any other finding this turn.
- **Recommended action:** None — informational. Recorded for the
  trail.
- **Confidence:** high

### Why this is the right call

The rule fired only to log a routine data point, not to flag a
deviation. A senior SRE notes it and moves on — escalating routine
load would train the operator to ignore the sentinel. Severity stays
at the rung the rule chose because investigation revealed nothing
worse.
