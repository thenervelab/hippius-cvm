"""Sentinel agent prompt assets + builders (PR-S6).

The static system prompt (`system.md`) and the worked few-shot
examples (`examples/*.md`) are authored as Markdown and shipped as
package data. `few_shot` assembles them into the agent's system
prompt; `render` builds the per-turn user prompt from live findings.
"""

from sentinel.prompts.few_shot import (
    FewShotExample,
    build_system_prompt,
    load_few_shot_examples,
    load_system_prompt,
)
from sentinel.prompts.render import aggregate_findings, build_user_prompt

__all__ = [
    "FewShotExample",
    "aggregate_findings",
    "build_system_prompt",
    "build_user_prompt",
    "load_few_shot_examples",
    "load_system_prompt",
]
