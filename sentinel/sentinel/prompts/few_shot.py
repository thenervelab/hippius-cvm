"""Loader for the sentinel system prompt + few-shot examples (PR-S6).

The prompt assets live as Markdown files beside this module so they can
be authored and reviewed as prose rather than buried in string
literals. `few_shot` reads them via `importlib.resources`, so loading
works identically from the source tree or an installed wheel (the
`*.md` files ship as package data — see `pyproject.toml`).

`build_system_prompt()` assembles the final system prompt once, at
agent construction: the role/rules section first, then the worked
examples that calibrate severity classification and output format.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources

_PACKAGE = "sentinel.prompts"
_SYSTEM_FILE = "system.md"
_EXAMPLES_DIR = "examples"

# Few-shot example files, in the order presented to the model:
# ascending severity, so it reads the calibration low → high.
_EXAMPLE_FILES: tuple[str, ...] = (
    "info_release_rate_normal.md",
    "alert_replay_attempts_spike.md",
    "critical_audit_chain_break.md",
)


@dataclass(frozen=True)
class FewShotExample:
    """One worked example loaded from `prompts/examples/`."""

    name: str  # file stem, e.g. "info_release_rate_normal"
    content: str  # the Markdown body


def load_system_prompt() -> str:
    """Read the raw system-prompt Markdown. Fails loudly if missing/empty."""

    text = (
        resources.files(_PACKAGE)
        .joinpath(_SYSTEM_FILE)
        .read_text(encoding="utf-8")
        .strip()
    )
    if not text:
        raise RuntimeError(f"{_PACKAGE}/{_SYSTEM_FILE} is empty")
    return text


def load_few_shot_examples() -> list[FewShotExample]:
    """Read every few-shot example, in ascending-severity order."""

    base = resources.files(_PACKAGE).joinpath(_EXAMPLES_DIR)
    examples: list[FewShotExample] = []
    for filename in _EXAMPLE_FILES:
        content = base.joinpath(filename).read_text(encoding="utf-8").strip()
        if not content:
            raise RuntimeError(f"{_PACKAGE}/{_EXAMPLES_DIR}/{filename} is empty")
        examples.append(
            FewShotExample(name=filename.removesuffix(".md"), content=content)
        )
    return examples


def build_system_prompt() -> str:
    """Assemble the full system prompt: base prompt + few-shot examples.

    Called once when the agent is constructed. Pure (no env, no clock),
    so the result is deterministic and the assembled prompt can be
    asserted on in tests.
    """

    parts: list[str] = [
        load_system_prompt(),
        "",
        "# Worked examples",
        "",
        "The examples below calibrate severity classification and the "
        "required output format. Study them, then apply the same "
        "discipline to the live findings.",
    ]
    for example in load_few_shot_examples():
        parts += ["", "---", "", example.content]
    return "\n".join(parts)
