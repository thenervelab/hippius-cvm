"""Shell-out wrapper for `hippius-ticket-validator read-miner-status`.

Spec of record: ARCHITECTURE.md §23. vali's scheduler reads the
**authoritative** on-chain miner state — never a miner's self-report
— from `pallet-compute-scoring` on a `thenervelab/thebrain` node.
The SCALE wire layout + Substrate storage-key hashing live in the
Rust binary (`binaries/ticket-validator/src/miner_status.rs`); this
module is the thin Python boundary.

Wire contract with the binary:

- the binary reads no stdin.
- the RPC endpoint is passed via the `THEBRAIN_RPC_URL` **environment
  variable** — never argv — so a credentialed URL never lands in
  `ps` output (§20 logging discipline).
- stdout: JSON, either `{"tag":"ok","current_epoch":N,"miners":[…]}`
  or `{"tag":"err","error":"…","category":"…"}`.
- exit: 0 ok, 2 structured read failure, 1 internal.

Fail-closed contract: **every** failure mode — binary missing, RPC
unreachable, structured error, schema drift — raises
[`ChainReadUnavailable`]. There is no "caller's fault" path: a
scheduler that cannot read the chain MUST NOT place (§23: "On a
stale/missing epoch the scheduler fails closed"). The view layer
maps `ChainReadUnavailable` to HTTP 503.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger("apps.scheduler.chain")


class ChainReadError(Exception):
    """Base class for chain-read failures."""


class ChainReadUnavailable(ChainReadError):
    """vali could not obtain a trustworthy on-chain snapshot.

    Mapped to HTTP 503. Covers binary-missing, RPC-unreachable,
    structured-error, and schema-drift — all of which the scheduler
    treats identically: fail closed, do not place.
    """


@dataclass(frozen=True)
class MinerView:
    """One miner as read off-chain.

    - `node_id`               §23 compute node_id, 64-char hex.
    - `status`                `active` | `quarantined` |
                              `decommissioned`.
    - `last_transition_epoch` epoch of the last `MinerStatus`
                              transition on-chain.
    - `data_epoch`            epoch the miner's score reflects
                              (`current_epoch` if scored this epoch,
                              else `last_transition_epoch`). The
                              stale-epoch gate keys off this.
    - `quality`               §23 reward weight (`u128`) reused as
                              the v1 quality signal; `0` if unscored.
    """

    node_id: str
    status: str
    last_transition_epoch: int
    data_epoch: int
    quality: int
    # The miner's announced price (`MinerPrice`, USD per resource-unit
    # ×1e6). `None` ⇒ the miner has not set a price — the scheduler's
    # price term is inert for it + the tenant ceiling never trips.
    price: int | None = None


@dataclass(frozen=True)
class ChainSnapshot:
    """A point-in-time read of `pallet-compute-scoring`."""

    current_epoch: int
    miners: tuple[MinerView, ...]
    # Is the configured pallet still WIRED INTO the runtime (present in
    # `state_getMetadata`)? A runtime upgrade that drops a pallet does
    # NOT delete its storage, and the reader derives its keys from the
    # pallet NAME (twox-128) over raw storage — so a removed pallet keeps
    # answering with its last-written bytes forever, and every read looks
    # healthy. `False` means this whole snapshot is a fossil.
    #
    # Defaults `True` — an older validator binary emits no such key, and
    # a version skew must never fabricate an alarm.
    pallet_live: bool = True


def read_miner_status() -> ChainSnapshot:
    """Shell out to `read-miner-status` and return a [`ChainSnapshot`].

    Raises [`ChainReadUnavailable`] on any failure. Never logs the
    RPC URL (it may embed a credential) — only diagnostic strings.

    **Removed-pallet (fossil) snapshots.** When the binary reports
    `pallet_live: false` the configured pallet is no longer in the
    runtime metadata while its orphaned storage prefix still answers
    reads — every value here is frozen and no on-chain state can change.
    That is logged at ERROR on every call. Whether it also FAILS the read
    is the operator's call, not this module's:
    `VALI_CHAIN_REQUIRE_PALLET_LIVE` (default **False**) keeps today's
    behaviour byte-identical — placement continues off the fossil, which
    is what production is doing right now and what an unannounced
    fail-closed flip would break. Set it True once the chain side is
    resolved, to make the fossil a hard 503 instead of a log line.
    """
    rpc_url = str(getattr(settings, "VALI_THEBRAIN_RPC_URL", "") or "").strip()
    if not rpc_url:
        # Fail loud + closed — a misconfigured deploy must not
        # silently behave as "no miners" (which would 409 every
        # placement); 503 surfaces the misconfiguration to ops.
        raise ChainReadUnavailable("VALI_THEBRAIN_RPC_URL is not configured")

    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ChainReadUnavailable(f"validator binary not found at {bin_path}")

    pallet = str(getattr(settings, "VALI_THEBRAIN_PALLET_NAME", "ComputeScoring"))
    timeout = float(getattr(settings, "VALI_THEBRAIN_RPC_TIMEOUT_S", 30.0))

    # The RPC URL goes through the environment, NOT argv. Inherit the
    # ambient env so the child keeps PATH etc.
    child_env = {**os.environ, "THEBRAIN_RPC_URL": rpc_url}

    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "read-miner-status", "--pallet-name", pallet],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("read-miner-status timed out after %.1fs", timeout)
        raise ChainReadUnavailable(
            f"read-miner-status timed out after {timeout:.1f}s"
        ) from exc
    except OSError as exc:
        log.error("read-miner-status spawn failed: %s", exc)
        raise ChainReadUnavailable(f"read-miner-status spawn failed: {exc}") from exc

    # Exit 0 (ok) and 2 (structured read failure) both write a JSON
    # envelope; exit 1 is an internal failure with no contract on
    # stdout. Anything non-zero is fail-closed.
    if completed.returncode not in (0, 2):
        log.error(
            "read-miner-status internal failure: rc=%s stderr=%r",
            completed.returncode,
            _safe_truncate(completed.stderr),
        )
        raise ChainReadUnavailable(
            f"read-miner-status exited with code {completed.returncode}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("read-miner-status non-JSON stdout (rc=%s)", completed.returncode)
        raise ChainReadUnavailable("read-miner-status stdout is not JSON") from exc

    if not isinstance(payload, dict) or "tag" not in payload:
        raise ChainReadUnavailable("read-miner-status stdout missing 'tag' field")

    tag = payload["tag"]
    if tag == "err":
        category = str(payload.get("category", "unknown"))
        message = str(payload.get("error", "chain read failed"))
        log.error("read-miner-status rejected: category=%s", category)
        raise ChainReadUnavailable(f"[{category}] {message}")
    if tag != "ok":
        raise ChainReadUnavailable(f"read-miner-status returned unknown tag={tag!r}")

    try:
        snapshot = _coerce_snapshot(payload)
    except (KeyError, TypeError, ValueError) as exc:
        # Schema drift between the Rust binary and this module is a
        # deployment bug — still fail closed (503), never place.
        raise ChainReadUnavailable(
            f"read-miner-status output has unexpected shape: {exc}"
        ) from exc

    if not snapshot.pallet_live:
        # The read SUCCEEDED and the data is dead. Loudest possible
        # signal short of failing: an operator watching `read-miner-status
        # ok` every 30 s has no other way to learn the difference.
        log.error(
            "read-miner-status FOSSIL: pallet %r is ABSENT from the runtime "
            "metadata but its orphaned storage prefix still answers reads — "
            "current_epoch=%d and %d miner(s) are the pallet's LAST-WRITTEN "
            "bytes, frozen forever. No on-chain state can change: no "
            "registration, no quarantine, no epoch close, prices frozen. "
            "Placement is running off a snapshot of a dead pallet.",
            pallet,
            snapshot.current_epoch,
            len(snapshot.miners),
        )
        if bool(getattr(settings, "VALI_CHAIN_REQUIRE_PALLET_LIVE", False)):
            raise ChainReadUnavailable(
                f"pallet {pallet!r} is absent from the runtime metadata "
                "(orphaned storage prefix) and "
                "VALI_CHAIN_REQUIRE_PALLET_LIVE is set"
            )

    log.info(
        "read-miner-status ok: current_epoch=%d miners=%d",
        snapshot.current_epoch,
        len(snapshot.miners),
    )
    return snapshot


def _coerce_snapshot(payload: dict[str, Any]) -> ChainSnapshot:
    """Project the validator JSON into the typed [`ChainSnapshot`].

    Raises `KeyError` / `TypeError` / `ValueError` on shape drift —
    the caller maps that to `ChainReadUnavailable`.
    """
    current_epoch = _coerce_int(payload["current_epoch"], "current_epoch")
    # OPTIONAL — absent means an OLDER validator binary that predates the
    # metadata probe, and MUST read as `True`: a validator/vali version
    # skew is not allowed to fabricate a fossil alarm. Present ⇒ strictly
    # a JSON bool (mirrors `_coerce_int`'s strictness, in reverse: an int
    # is not a bool), so schema drift fails closed rather than silently
    # truthy-casting some other shape into a health claim.
    pallet_live = _coerce_bool(payload.get("pallet_live", True), "pallet_live")
    miners_raw = payload.get("miners")
    if not isinstance(miners_raw, list):
        raise TypeError("'miners' must be a list")

    miners: list[MinerView] = []
    for entry in miners_raw:
        if not isinstance(entry, dict):
            raise TypeError("each miner entry must be an object")
        miners.append(
            MinerView(
                node_id=str(entry["node_id_hex"]),
                status=str(entry["status"]),
                last_transition_epoch=_coerce_int(
                    entry["last_transition_epoch"], "last_transition_epoch"
                ),
                data_epoch=_coerce_int(entry["data_epoch"], "data_epoch"),
                # `quality_dec` is a decimal STRING — the §23 weight
                # is a u128, outside JSON's safe-integer range.
                quality=int(str(entry["quality_dec"])),
                # `price_dec` is an OPTIONAL decimal STRING — absent ⇒ the
                # miner has not announced a price.
                price=(
                    int(str(entry["price_dec"]))
                    if entry.get("price_dec") is not None
                    else None
                ),
            )
        )
    return ChainSnapshot(
        current_epoch=current_epoch,
        miners=tuple(miners),
        pallet_live=pallet_live,
    )


class ChainWriteUnavailable(ChainReadError):
    """vali could not POST the epoch weights to the chain (binary
    missing / RPC unreachable / extrinsic rejected). Producing the
    EpochWeights is best-effort from the scheduler's view — a failed
    submit is retried next epoch, never blocks placement."""


def submit_epoch_close(weights: dict[str, int]) -> None:
    """Post the per-miner reward weights for the next epoch via the
    pallet's root-only `vali_submit_epoch_close`.

    Mirrors [`read_miner_status`]: shells out to
    `hippius-ticket-validator submit-epoch-close`, which constructs,
    signs (with the vali authority key at `VALI_THEBRAIN_SIGNING_KEY_PATH`)
    and submits the extrinsic over the RPC (URL via env, never argv). The
    weights are piped as JSON on stdin — `u128` is carried as a DECIMAL
    STRING (JSON can't hold it as a number).

    `weights` is `{node_id_hex: weight_u128}`; an empty dict is a no-op
    (nothing bound to score this epoch). Raises [`ChainWriteUnavailable`]
    on any failure — the caller logs + retries next epoch.

    NOTE: the `submit-epoch-close` subcommand is the deploy-time
    integration piece (the extrinsic signer needs the live chain's
    signing params); until it is built + a testnet is up, this seam
    surfaces `ChainWriteUnavailable` cleanly.
    """
    if not weights:
        return

    rpc_url = str(getattr(settings, "VALI_THEBRAIN_RPC_URL", "") or "").strip()
    if not rpc_url:
        raise ChainWriteUnavailable("VALI_THEBRAIN_RPC_URL is not configured")
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ChainWriteUnavailable(f"validator binary not found at {bin_path}")
    signing_key = str(getattr(settings, "VALI_THEBRAIN_SIGNING_KEY_PATH", "") or "").strip()
    if not signing_key:
        raise ChainWriteUnavailable("VALI_THEBRAIN_SIGNING_KEY_PATH is not configured")
    pallet = str(getattr(settings, "VALI_THEBRAIN_PALLET_NAME", "ComputeScoring"))
    timeout = float(getattr(settings, "VALI_THEBRAIN_RPC_TIMEOUT_S", 30.0))

    # Deterministic order (node_id) so a re-run / golden diff is stable.
    payload = json.dumps(
        [
            {"node_id": node_id, "weight": str(weight)}
            for node_id, weight in sorted(weights.items())
        ]
    ).encode("utf-8")
    child_env = {**os.environ, "THEBRAIN_RPC_URL": rpc_url}

    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [
                str(bin_path),
                "submit-epoch-close",
                "--pallet-name",
                pallet,
                "--signing-key",
                signing_key,
            ],
            input=payload,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ChainWriteUnavailable(
            f"submit-epoch-close timed out after {timeout:.1f}s"
        ) from exc
    except OSError as exc:
        raise ChainWriteUnavailable(f"submit-epoch-close spawn failed: {exc}") from exc

    if completed.returncode != 0:
        raise ChainWriteUnavailable(
            f"submit-epoch-close failed (rc={completed.returncode}): "
            f"{_safe_truncate(completed.stderr)}"
        )
    log.info("submitted epoch-close weights for %d miner(s)", len(weights))


def _coerce_int(value: Any, field: str) -> int:
    """Strict JSON-integer coercion (rejects bool, float, str)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be a JSON integer")
    return value


def _coerce_bool(value: Any, field: str) -> bool:
    """Strict JSON-boolean coercion — the mirror of [`_coerce_int`].

    `_coerce_int` rejects a bool for an int; this rejects an int (or a
    string, or `None`) for a bool. No truthiness: a health claim built
    out of `bool("false")` is worse than no claim at all, so shape drift
    raises and the caller fails closed.
    """
    if not isinstance(value, bool):
        raise TypeError(f"{field} must be a JSON boolean")
    return value


def _safe_truncate(b: bytes, limit: int = 512) -> str:
    """Stderr capture for ops logs. The binary's stderr contract is
    diagnostic strings only — never the RPC URL or secrets.
    """
    if not b:
        return ""
    s = b.decode("utf-8", errors="replace")
    if len(s) > limit:
        return s[:limit] + f"...<+{len(s) - limit} chars>"
    return s


@dataclass(frozen=True)
class PriceAnnouncement:
    """One announced-but-not-yet-effective miner price change.

    - `node_id`         §23 compute node_id, 64-char hex.
    - `new_price`       the price (u128, USD per resource-unit ×1e6)
                        that becomes effective at `effective_block`.
    - `effective_block` the block at which `new_price` bites.
    """

    node_id: str
    new_price: int
    effective_block: int


@dataclass(frozen=True)
class PendingPriceReport:
    """A point-in-time read of the pallet's `PendingPriceChange` map."""

    current_block: int
    announcements: tuple[PriceAnnouncement, ...]


def read_pending_price_changes() -> PendingPriceReport:
    """Shell out to `read-pending-prices` and return the announced
    miner price changes + the chain's current block.

    Mirrors [`read_miner_status`]: RPC URL via env (never argv), JSON
    envelope on stdout, fail-closed on every failure
    ([`ChainReadUnavailable`]). The price-migration watcher needs the
    block (not just the epoch) to size the migration notice window.

    Wire contract: stdout `{"tag":"ok","current_block":N,"changes":[
    {"node_id_hex":..,"new_price_dec":"..","effective_block":N}]}` or
    `{"tag":"err",...}`. `new_price_dec` is a decimal STRING (u128).

    NOTE: the `read-pending-prices` subcommand is the deploy-time piece
    (the Rust reader must decode `PendingPriceChange`); until it exists
    this seam surfaces `ChainReadUnavailable` cleanly, so the watcher is
    inert in production rather than wrong.
    """
    rpc_url = str(getattr(settings, "VALI_THEBRAIN_RPC_URL", "") or "").strip()
    if not rpc_url:
        raise ChainReadUnavailable("VALI_THEBRAIN_RPC_URL is not configured")
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ChainReadUnavailable(f"validator binary not found at {bin_path}")

    pallet = str(getattr(settings, "VALI_THEBRAIN_PALLET_NAME", "ComputeScoring"))
    timeout = float(getattr(settings, "VALI_THEBRAIN_RPC_TIMEOUT_S", 30.0))
    child_env = {**os.environ, "THEBRAIN_RPC_URL": rpc_url}

    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "read-pending-prices", "--pallet-name", pallet],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ChainReadUnavailable(
            f"read-pending-prices timed out after {timeout:.1f}s"
        ) from exc
    except OSError as exc:
        raise ChainReadUnavailable(
            f"read-pending-prices spawn failed: {exc}"
        ) from exc

    if completed.returncode not in (0, 2):
        raise ChainReadUnavailable(
            f"read-pending-prices exited with code {completed.returncode}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ChainReadUnavailable("read-pending-prices stdout is not JSON") from exc

    if not isinstance(payload, dict) or "tag" not in payload:
        raise ChainReadUnavailable("read-pending-prices stdout missing 'tag'")
    tag = payload["tag"]
    if tag == "err":
        category = str(payload.get("category", "unknown"))
        message = str(payload.get("error", "chain read failed"))
        raise ChainReadUnavailable(f"[{category}] {message}")
    if tag != "ok":
        raise ChainReadUnavailable(f"read-pending-prices unknown tag={tag!r}")

    try:
        return _coerce_price_report(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ChainReadUnavailable(
            f"read-pending-prices output has unexpected shape: {exc}"
        ) from exc


def _coerce_price_report(payload: dict[str, Any]) -> PendingPriceReport:
    current_block = _coerce_int(payload["current_block"], "current_block")
    changes_raw = payload.get("changes")
    if not isinstance(changes_raw, list):
        raise TypeError("'changes' must be a list")
    changes: list[PriceAnnouncement] = []
    for entry in changes_raw:
        if not isinstance(entry, dict):
            raise TypeError("each change entry must be an object")
        changes.append(
            PriceAnnouncement(
                node_id=str(entry["node_id_hex"]),
                # u128 carried as a decimal STRING (outside JSON int range).
                new_price=int(str(entry["new_price_dec"])),
                effective_block=_coerce_int(
                    entry["effective_block"], "effective_block"
                ),
            )
        )
    return PendingPriceReport(
        current_block=current_block, announcements=tuple(changes)
    )
