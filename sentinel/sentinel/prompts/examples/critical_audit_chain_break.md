# Example — CRITICAL: KBS audit chain break

### Situation given to the sentinel

```
### [CRITICAL] audit_chain_break
- summary: KBS audit chain verification FAILED — recomputed head does
  not match the stored head.sha256.
- fingerprint: chain-break:record-2287
- details: {"first_bad_seq": 2287, "expected_head": "…", "actual_head": "…"}
```

### Model response

## [CRITICAL] KBS audit log has been tampered — attestation root broken
- **Rule:** audit_chain_break
- **Detected:** 2026-05-18T16:04:00Z
- **Assessment:** The KBS audit hash chain no longer verifies: the
  recomputed head diverges from the stored `head.sha256` starting at
  record 2287. Either the log was edited after the fact or records
  were dropped. Until this is resolved the external attestation root
  cannot be trusted — and the scheduled anchor publisher must be
  halted, because a fresh anchor would notarise a compromised chain.
- **Recommended action:** Page the on-call security engineer now.
  Halt the scheduled anchor publisher, freeze KBS audit-log writers,
  preserve the current `audit.log` and `head.sha256` for forensics,
  and reconcile against the last known-good anchor in the S3
  `audit-anchors` bucket to bound when the divergence began.
- **Confidence:** high

### Why this is the right call

A broken audit chain is the canonical CRITICAL: it is an integrity
failure, not a load anomaly, so it pages a human immediately. The
senior SRE leads with the emergency, states plainly what is no longer
trustworthy, and flags the follow-on risk — that the scheduled anchor
publisher would otherwise notarise the bad chain. Never under-call a
tamper signal.
