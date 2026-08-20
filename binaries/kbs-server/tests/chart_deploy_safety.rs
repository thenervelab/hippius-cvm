//! Deployment-safety: the suppressed-confirm anti-rollback gate
//! (`kbs_core::volume_stamp`) MUST ship DISABLED in
//! `deploy/gitops/apps/kbs` until every legacy VM in the fleet has been
//! re-baked to send confirms — see `config::Config::
//! resolve_max_unconfirmed_releases` for the full deployment-hazard
//! writeup.
//!
//! This test asserts against the ACTUAL RENDERED chart output, not the
//! Rust compiled default and not the `values.yaml` source text read as
//! a string. "The chart renders something OTHER than what the compiled
//! default would produce" is exactly the failure mode this item exists
//! to catch — a re-sync that silently drops the override (the same
//! class of bug `requireWrappedKek`'s comment already documents for
//! this chart), or an edit that touches the wrong file. A test that
//! only inspected the Rust side would pass even if the chart itself
//! were broken or the override had been deleted.
//!
//! Requires `helm` on `PATH` (present in dev + CI images that already
//! lint this chart). Fails loudly rather than skipping if it is
//! missing — a silently-skipped deployment-safety check is worse than
//! an environment gap that gets noticed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_kbs_server::config::Config;
use std::path::PathBuf;
use std::process::Command;

fn chart_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/gitops/apps/kbs")
}

/// Render `templates/configmap-kbs.yaml` with `helm template` and pull
/// out the embedded `config.toml` block's literal body — the SAME
/// bytes the real KBS pod mounts into `/etc/kbs-config/config.toml`
/// and parses at boot.
fn render_config_toml() -> String {
    let dir = chart_dir();
    assert!(
        dir.join("Chart.yaml").is_file(),
        "chart directory not found at {} — the CARGO_MANIFEST_DIR-relative path assumption \
         broke (did `deploy/gitops/apps/kbs` move?)",
        dir.display()
    );
    let output = Command::new("helm")
        .args([
            "template",
            "kbs",
            ".",
            "--show-only",
            "templates/configmap-kbs.yaml",
        ])
        .current_dir(&dir)
        .output()
        .expect("`helm` must be on PATH to run this deployment-safety check");
    assert!(
        output.status.success(),
        "helm template failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).unwrap();

    // Pull the `config.toml: |` YAML block-literal body out of the
    // rendered ConfigMap. The block is indented 4 spaces under `data:`;
    // it ends at the first non-blank line that isn't indented that far.
    let mut in_block = false;
    let mut toml_lines: Vec<&str> = Vec::new();
    for line in rendered.lines() {
        if !in_block {
            if line.trim_start() == "config.toml: |" {
                in_block = true;
            }
            continue;
        }
        match line.strip_prefix("    ") {
            Some(stripped) => toml_lines.push(stripped),
            None if line.trim().is_empty() => toml_lines.push(""),
            None => break, // dedent — the block literal ended
        }
    }
    assert!(
        !toml_lines.is_empty(),
        "did not find a `config.toml: |` block in the rendered ConfigMap:\n{rendered}"
    );
    toml_lines.join("\n")
}

#[test]
fn the_suppressed_confirm_bound_is_always_rendered_explicitly() {
    // This guard held the fuse shut while the fleet could not confirm, and
    // it fired on the arming commit (2026-08-13) exactly as intended — the
    // gate was armed only after `?bound=3` came back non-vacuously green
    // with all four blessed distros at `has_ever_confirmed=true`.
    //
    // The post-arming invariant is NOT "the bound is 3". Picking the value
    // is an operator decision and this test must not re-litigate it. What
    // must never happen is the bound going UNSTATED: `max_unconfirmed_releases`
    // is `#[serde(default)]`, so an absent key silently resolves to the
    // compiled default and the deployed posture becomes unreadable from the
    // rendered config — which is the failure mode the whole "render it
    // explicitly" discipline in values.yaml exists to prevent, in BOTH
    // directions (silently armed, and silently disabled).
    let toml = render_config_toml();
    let effective: String = toml
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        effective.contains("max_unconfirmed_releases ="),
        "the rendered config.toml does not state `max_unconfirmed_releases` at all — the \
         binary would fall back to its compiled default and the deployed anti-rollback \
         posture would be invisible in the rendered config. Rendered TOML was:\n{toml}"
    );

    // Round-trip through the EXACT parser the binary uses, so a renamed key
    // or a type change fails here instead of at boot.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), &toml).unwrap();
    let cfg = Config::load(f.path()).expect("the rendered chart config.toml must parse");
    assert!(
        cfg.storage.max_unconfirmed_releases.is_some(),
        "the rendered config parsed to None for max_unconfirmed_releases — that is the \
         absent-key state, i.e. armed at the compiled default by accident rather than by \
         decision"
    );
}

// ── admin mTLS: the chart cannot render a self-inflicted outage ──────

/// Render `configmap-kbs.yaml` with extra `--set` overrides. Returns
/// `(success, stdout, stderr)` so a test can assert on a DELIBERATE
/// render failure as well as on the rendered bytes.
fn try_render(sets: &[&str]) -> (bool, String, String) {
    let dir = chart_dir();
    let mut args: Vec<String> = [
        "template",
        "kbs",
        ".",
        "--show-only",
        "templates/configmap-kbs.yaml",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    for s in sets {
        args.push("--set".to_string());
        args.push((*s).to_string());
    }
    let output = Command::new("helm")
        .args(&args)
        .current_dir(&dir)
        .output()
        .expect("`helm` must be on PATH to run this deployment-safety check");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Extract the `config.toml: |` block literal out of a rendered
/// ConfigMap (same shape as `render_config_toml`, over arbitrary bytes).
fn extract_toml(rendered: &str) -> String {
    let mut in_block = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in rendered.lines() {
        if !in_block {
            if line.trim_start() == "config.toml: |" {
                in_block = true;
            }
            continue;
        }
        match line.strip_prefix("    ") {
            Some(stripped) => lines.push(stripped),
            None if line.trim().is_empty() => lines.push(""),
            None => break,
        }
    }
    assert!(
        !lines.is_empty(),
        "no `config.toml: |` block in:\n{rendered}"
    );
    lines.join("\n")
}

#[test]
fn require_mtls_cannot_be_flipped_before_the_material_exists() {
    // `AdminListenerMode::decide` answers `Refuse` for require_mtls=true
    // + no material: the admin listener is NOT bound, which means no
    // register-vm (no launches), no §25 activate (no migrations), no
    // allowlist reload. Every one of those is a fleet outage, and the
    // flag is a one-word edit in a values file.
    //
    // The runbook says "material first, flag last". This makes the wrong
    // order UN-RENDERABLE rather than merely documented — the difference
    // between a procedure and a guarantee.
    // `admin.mtls.secretName=` is cleared EXPLICITLY. The shipped values
    // now carry the material (cutover, 2026-08-13), so a render that
    // inherited them would be testing the deployment instead of the gate,
    // and would pass for the wrong reason the day someone unmounts it.
    let (ok, _out, stderr) = try_render(&["admin.requireMtls=true", "admin.mtls.secretName="]);
    assert!(
        !ok,
        "the chart rendered require_mtls=true with no admin TLS material — that config \
         leaves the lifecycle admin API unbound"
    );
    assert!(
        stderr.contains("REFUSES to serve the admin listener"),
        "the render failed for the wrong reason: {stderr}"
    );
}

#[test]
fn material_plus_the_flag_renders_the_enforcing_config() {
    // The end state the cutover reaches, round-tripped through the REAL
    // parser AND the REAL decision function — so a renamed key or a
    // typo'd path in the chart fails here instead of at boot.
    let (ok, out, stderr) = try_render(&[
        "admin.requireMtls=true",
        "admin.mtls.secretName=kbs-admin-tls",
    ]);
    assert!(ok, "helm template failed: {stderr}");

    let toml = extract_toml(&out);
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), &toml).unwrap();
    let cfg = Config::load(f.path()).expect("the rendered enforcing config.toml must parse");
    let admin = cfg.admin.expect("[admin] must be rendered");
    assert!(admin.require_mtls);
    assert!(
        matches!(
            hippius_kbs_server::admin_tls::AdminListenerMode::decide(&admin),
            hippius_kbs_server::admin_tls::AdminListenerMode::Mtls(_)
        ),
        "the enforcing render must decide Mtls, not Refuse/PlaintextOptIn"
    );
}

#[test]
fn mounting_the_material_enforces_mtls_even_with_the_flag_still_false() {
    // The property that shapes the whole rollout order, asserted against
    // the CHART rather than only the unit test: there is no "certs
    // mounted, still plaintext" state to rehearse in. An operator who
    // reads `requireMtls: false` as "not yet enforcing" and mounts the
    // Secret has already cut over — and vali must move in the same
    // window.
    // `requireMtls=false` is forced EXPLICITLY. The shipped values now set
    // it true (the cutover's last step), so a render that inherited them
    // would exercise the flag path and never test the property this whole
    // rollout order rests on — that the MATERIAL alone enforces. Third
    // time a guard in this file leaned on a shipped default; the pattern
    // is the bug, not the value.
    let (ok, out, stderr) = try_render(&[
        "admin.mtls.secretName=kbs-admin-tls",
        "admin.requireMtls=false",
    ]);
    assert!(ok, "helm template failed: {stderr}");
    let toml = extract_toml(&out);
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), &toml).unwrap();
    let cfg = Config::load(f.path()).unwrap();
    let admin = cfg.admin.expect("[admin] must be rendered");
    assert!(!admin.require_mtls, "this render must keep the flag false");
    assert!(
        matches!(
            hippius_kbs_server::admin_tls::AdminListenerMode::decide(&admin),
            hippius_kbs_server::admin_tls::AdminListenerMode::Mtls(_)
        ),
        "material present must ENFORCE mTLS regardless of require_mtls — if this ever \
         becomes PlaintextOptIn, the admin API silently reverts to unauthenticated"
    );
}

// ── the monitor's expectation is pinned to THIS chart ────────────────

/// Pull the single-line `kbsExpectedPosture:` value out of the vali
/// chart's values.yaml. Hand-parsed rather than YAML-deserialised: the
/// value is one quoted JSON scalar, and adding a YAML dependency to
/// read one line would be more machinery than the thing it reads.
fn vali_declared_posture() -> serde_json::Map<String, serde_json::Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/gitops/apps/vali/values.yaml");
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let matches: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("kbsExpectedPosture:"))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `kbsExpectedPosture:` in the vali values.yaml, found {}",
        matches.len()
    );
    let raw = matches[0].trim().trim_matches('\'').trim_matches('"');
    serde_json::from_str::<serde_json::Value>(raw)
        .unwrap_or_else(|e| panic!("vali `kbsExpectedPosture` is not valid JSON: {e} — {raw}"))
        .as_object()
        .expect("vali `kbsExpectedPosture` must be a JSON object")
        .clone()
}

#[test]
fn the_monitors_expected_posture_matches_what_this_chart_renders() {
    // ## What this pins, and why it is here rather than in vali's tests
    //
    // `apps.synthetic.checks.check_kbs_config_drift` diffs vali's
    // declared `VALI_KBS_EXPECTED_POSTURE` against what the RUNNING
    // kbs-server reports, every ~15 minutes. That check is only as
    // truthful as its declaration: if the declaration were free to drift
    // from the KBS chart, a green check would mean "the process matches
    // a number vali made up", which is a worse lie than no check at all.
    //
    // So the declaration is pinned HERE, to the bytes the KBS pod
    // actually mounts: `helm template` the KBS chart, parse it with the
    // REAL `Config` parser, derive the posture with the REAL
    // `wiring::config_posture` (the same function the endpoint serves),
    // and require every declared key to agree. Editing
    // `deploy/gitops/apps/kbs/values.yaml` without editing
    // `deploy/gitops/apps/vali/values.yaml` fails CI.
    //
    // That is what lets the monitor compare git↔process WITHOUT
    // cluster-API credentials: the ConfigMap↔git half is what ArgoCD
    // genuinely does check, and this test is what makes vali's mirror of
    // the git half exact.
    let toml = render_config_toml();
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), &toml).unwrap();
    let cfg = Config::load(f.path()).expect("the rendered chart config.toml must parse");
    let posture = serde_json::to_value(hippius_kbs_server::wiring::config_posture(&cfg)).unwrap();
    let posture = posture.as_object().unwrap();

    let declared = vali_declared_posture();
    assert!(
        !declared.is_empty(),
        "vali declares an EMPTY expected posture — the drift check would verify nothing"
    );
    for (key, want) in &declared {
        let got = posture.get(key).unwrap_or_else(|| {
            panic!(
                "vali declares posture key {key:?}, which the KBS does not report. Valid keys \
                 are the fields of `AdminConfigPostureResponse`: {:?}",
                posture.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(
            got, want,
            "vali's VALI_KBS_EXPECTED_POSTURE says {key} = {want}, but this chart renders a \
             config that resolves to {key} = {got}. One of the two files was edited without \
             the other — and until they agree, the 15-minute drift check is comparing the \
             running KBS against a number nothing produced."
        );
    }
}

#[test]
fn the_shipped_values_render_a_listener_that_authenticates() {
    // This guard was written as "shipping the client half must not flip
    // the live listener", and it held that line correctly through §3. The
    // cutover (§4, 2026-08-13) is the deliberate crossing it existed to
    // force someone to look at, so it now guards the far side.
    //
    // The post-cutover invariant is that the rendered listener is never
    // unauthenticated. `AdminListenerMode::decide` enforces mTLS on
    // material present whatever `require_mtls` says, so the only shape
    // that must never render is BOTH absent: plaintext with no client CA.
    // `require_mtls = false` on its own is fine and expected — it is the
    // last flag of the cutover and removes only the fallback.
    // Comments are STRIPPED before matching. The first version of this
    // check read `require_mtls = true` out of the ConfigMap's own
    // explanatory comment ("`require_mtls = true` + no material ⇒ the
    // binary REFUSES to bind") and therefore passed against a rendered
    // plaintext listener — a guard satisfied by prose about the thing it
    // was meant to measure. Caught by mutating the shipped values and
    // watching it still pass.
    let toml = render_config_toml();
    let effective: String = toml
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let has_material = effective.contains("client_ca_path");
    let requires = effective.contains("require_mtls = true");
    assert!(
        has_material || requires,
        "the shipped values render an admin listener with NO client CA and \
         require_mtls=false — that is the unauthenticated plaintext arm, on the \
         API that decides which host may unlock a VM. Rendered TOML was:\n{toml}"
    );
}
