"""§24/§25 state machine — legal transitions + required attestations.

This module is the **single authority** on which transitions vali
accepts. The Django view delegates here so the rule set is testable
without HTTP.

Mirror of `kbs_core::lifecycle::VmState` transitions (vali's intent
side; the KBS independently enforces its own `check_releasable`):

  Active → Active                               (no-op)
  Active → Migrating(new_gen, dest)             (begin §25 migration)
  Active → Decommissioning                      (begin §24 EOL)
  Migrating(new_gen) → Active(new_gen, dest)    (migration completes;
                                                 requires source-side
                                                 stopped-ack)
  Migrating → Decommissioning                   (abandon migration; the
                                                 destination never
                                                 activated)
  Decommissioning → Destroyed(gen)              (commit; requires
                                                 stopped-ack for the
                                                 current generation)

Anything else is rejected at the view boundary. In particular:
  - `Destroyed` is terminal: no transition out.
  - `Active → Destroyed` is rejected — must go through Decommissioning
    so the EOL nonce + stopped-ack flow runs.
  - `Migrating → Active(old_gen)` (rollback) is rejected — per §25
    once a migration commits to a new generation the old one is
    fenced; rollback is a NEW migration (Active(new_gen) → Migrating(…,
    old_host)).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import VmState


class TransitionError(Exception):
    """A transition was rejected for a *non-ack* reason — bad shape,
    wrong source state, missing fields, terminal state, etc. The view
    surfaces this as HTTP 400 with the message as the body.
    """

    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.message = message
        self.category = category


# Stable category strings — kept in sync with the view's error
# vocabulary so the Django consumer can map each to a code.
CAT_ILLEGAL = "illegal-transition"
CAT_MISSING_FIELD = "missing-field"
CAT_GENERATION = "generation-mismatch"


@dataclass(frozen=True)
class TransitionRequest:
    """Caller-supplied payload for `POST /v1/vm/<id>/transition`.

    All fields are typed; the view's serializer is the only path that
    constructs these so the rules below trust the types.
    """

    to_state: VmState
    if_version: int
    # Required for Active → Migrating, Migrating → Active.
    new_generation: int | None = None
    migration_dest: str | None = None
    # Hex-encoded signed StoppedAck CBOR. Required for the two
    # transitions that demand it (see `requires_stopped_ack` below).
    signed_stopped_ack_hex: str | None = None


def requires_stopped_ack(from_state: VmState, to_state: VmState) -> bool:
    """Two and only two transitions require a guest-signed stopped-ack:

    - `Decommissioning → Destroyed` (§24 — "no zombie that could
      re-attest"; the orchestrator MUST have proof THIS generation
      will not run again before flipping to the Destroyed tombstone).
    - `Migrating → Active` (§25 — destination cannot activate until
      the source side acks; otherwise an authorized split-brain).
    """
    return (from_state, to_state) in {
        (VmState.DECOMMISSIONING, VmState.DESTROYED),
        (VmState.MIGRATING, VmState.ACTIVE),
    }


def legal(from_state: VmState, to_state: VmState) -> bool:
    """Return True iff the source→target pair is in the §24/§25
    transition table above.

    No-ops (`Active → Active`, etc.) are NOT legal — they're a sign
    the caller is confused; the view returns 400 rather than
    silently accept.
    """
    pair = (from_state, to_state)
    return pair in _LEGAL_TRANSITIONS


_LEGAL_TRANSITIONS: frozenset[tuple[VmState, VmState]] = frozenset(
    {
        (VmState.ACTIVE, VmState.MIGRATING),
        (VmState.ACTIVE, VmState.DECOMMISSIONING),
        (VmState.MIGRATING, VmState.ACTIVE),
        (VmState.MIGRATING, VmState.DECOMMISSIONING),
        (VmState.DECOMMISSIONING, VmState.DESTROYED),
    }
)


def required_args(to_state: VmState, req: TransitionRequest) -> None:
    """Raise `TransitionError` if `req` is missing fields needed for
    the target state.

    - `Migrating` target: must carry `new_generation` + `migration_dest`.
    - `Active` target (i.e. completing a migration): must carry
      `new_generation` (the gen the destination is moving to).
    """
    if to_state == VmState.MIGRATING:
        if req.new_generation is None:
            raise TransitionError(
                "new_generation required for Migrating target", CAT_MISSING_FIELD
            )
        if not req.migration_dest:
            raise TransitionError(
                "migration_dest required for Migrating target", CAT_MISSING_FIELD
            )
    if to_state == VmState.ACTIVE:
        if req.new_generation is None:
            raise TransitionError(
                "new_generation required for Active target "
                "(completing Migrating)",
                CAT_MISSING_FIELD,
            )
