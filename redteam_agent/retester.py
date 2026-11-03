"""Retester: the dedicated reproduction role.

ARTEX runs retests as their own agent with their own prompt and an explicit
verdict contract (`agent/retester.go`): **reproduced / fixed / inconclusive**,
with an evidence bar per verdict and an instruction to argue the opposite case
before saving. The harness used to inline this as ``_confirm``. Extracting it
does three things:

* the reproduction check gets its own vocabulary, so a "not reproduced" result
  is not confused with "clean" or "budget exhausted";
* the strategy (variant payload under the same evasion, or an exact replay for
  chains) lives in one place instead of inside the agent loop;
* the agent loop stays planner-shaped: it schedules, the retester judges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class RetestVerdict(str, Enum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"


SendFn = Callable[[list[Any], str, str], tuple[Any, Any, int] | None]


@dataclass
class RetestResult:
    verdict: RetestVerdict = RetestVerdict.INCONCLUSIVE
    technique: str = ""
    indicators: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def confirmed(self) -> bool | None:
        """True/False for a decided retest, None when it could not decide."""
        if self.verdict is RetestVerdict.REPRODUCED:
            return True
        if self.verdict is RetestVerdict.NOT_REPRODUCED:
            return False
        return None


class Retester:
    """Plays the reproduction strategy and applies the evidence bar."""

    name = "retester"

    def __init__(self, logger: Callable[[str], None] | None = None) -> None:
        self.log = logger or (lambda _m: None)

    # -- strategy -------------------------------------------------------
    def retest(
        self,
        *,
        attack: Any,
        messages: list[Any],
        payload: str,
        mutation_name: str,
        alternatives: list[str],
        send: SendFn,
    ) -> RetestResult:
        """Send one reproduction probe and classify the result.

        A chain or a single-payload attack replays the exact request, which still
        catches a non-deterministic detector. Otherwise the same evasion is
        reapplied to a second payload, so a reproduced finding can't be an
        artifact of one hand-written prompt.
        """
        is_chain = bool(attack.multi_turn) and len(messages) > 1
        if is_chain or not alternatives:
            technique = "replay"
            variant = payload
            alt_messages = [type(m)(role=m.role, content=m.content) for m in messages]
        else:
            variant_payload = alternatives[0]
            if mutation_name == "none":
                variant = variant_payload
            else:
                from .mutators import apply_mutation

                variant, _note = apply_mutation(mutation_name, variant_payload)
            technique = f"variant-payload+{mutation_name}"
            alt_messages = [
                type(m)(role=m.role, content=variant if m.role == "user" else m.content)
                for m in messages
            ]

        outcome = send(alt_messages, variant, technique)
        if outcome is None:
            return RetestResult(
                verdict=RetestVerdict.INCONCLUSIVE,
                technique=technique,
                notes="retest not sent: budget exhausted or transport error",
            )

        probe, verdict, _seq = outcome
        indicators = list(getattr(verdict, "indicators", []) or [])
        tool_calls = list(getattr(probe, "tool_calls", []) or [])

        # Evidence bar: a finding needs an indicator or an actual tool call. A
        # judge that flips without either is a detector artifact, not a proof.
        if getattr(verdict, "finding", False) and (indicators or tool_calls):
            return RetestResult(
                verdict=RetestVerdict.REPRODUCED,
                technique=technique,
                indicators=indicators,
                notes=f"{len(indicators)} indicator(s), {len(tool_calls)} tool call(s)",
            )
        if getattr(probe, "ok", False) and not getattr(verdict, "finding", False):
            return RetestResult(
                verdict=RetestVerdict.NOT_REPRODUCED,
                technique=technique,
                indicators=indicators,
                notes=f"probe ok, no indicator ({getattr(verdict, 'reasoning', '')[:120]})",
            )
        return RetestResult(
            verdict=RetestVerdict.INCONCLUSIVE,
            technique=technique,
            indicators=indicators,
            notes="probe failed or judge was unavailable",
        )
