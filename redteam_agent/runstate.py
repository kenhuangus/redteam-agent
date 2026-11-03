"""Run state: terminal reasons and the intent frontier.

Two ideas are borrowed from ARTEX (`agent/planner.go`, `agent/worker.go`,
`agent/terminalreason.go`, `agent/stagnation_test.go`):

* A run ends for a *named* reason, never a free-form string, so a gate or a
  dashboard can act on it. ``StopReason`` is the enum ARTEX keeps in
  ``harness.TerminalReason``, trimmed to what a single-target harness needs.
* The planner yields *intents* and a worker claims exactly one. Our old planner
  handed out attacks directly and lost the lifecycle: an attack that had been
  started but not finished looked the same as an untested one once the process
  restarted. ``Frontier`` keeps that lifecycle (open -> done / exhausted /
  blocked / dropped) so the report can distinguish "not run" from "ran, found
  nothing", and a dropped direction is recorded with a reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class StopReason(str, Enum):
    """Named terminal reasons. Values are the strings the report has always used."""

    ATTACKS_EXHAUSTED = "attack set exhausted"
    PROBE_BUDGET = "probe budget exhausted"
    TURN_BUDGET = "turn budget exhausted"
    STAGNATION = "stagnation detected"
    TARGET_UNHEALTHY = "target unhealthy: repeated probe errors"
    CRITICAL_GATE = "stop_on_critical gate hit"
    OPERATOR = "operator requested stop"
    ERROR = "internal error"


class IntentStatus(str, Enum):
    OPEN = "open"
    RUNNING = "running"
    DONE = "done"          # a finding was recorded for this direction
    EXHAUSTED = "exhausted"  # every scheduled payload/mutation ran, nothing found
    BLOCKED = "blocked"      # blocked by policy or a dead target, not explored
    DROPPED = "dropped"      # planner gave up on the direction (stagnation)


@dataclass
class Intent:
    """One unit of planned work: an attack and the route the planner scheduled."""

    attack_id: str
    category: str
    route: tuple[str, ...] = ()
    status: IntentStatus = IntentStatus.OPEN
    attempts: int = 0
    findings: int = 0
    reason: str = ""

    @property
    def settled(self) -> bool:
        return self.status not in (IntentStatus.OPEN, IntentStatus.RUNNING)


@dataclass
class Frontier:
    """The planner's open set of directions, with a worker-style claim/settle."""

    intents: dict[str, Intent] = field(default_factory=dict)

    def register(self, attack_id: str, category: str, route: tuple[str, ...] = ()) -> Intent:
        intent = Intent(attack_id=attack_id, category=category, route=route)
        self.intents[attack_id] = intent
        return intent

    def get(self, attack_id: str) -> Intent | None:
        return self.intents.get(attack_id)

    def claim(self, attack_id: str) -> Intent | None:
        """Mark an intent running; only an open intent can be claimed."""
        intent = self.intents.get(attack_id)
        if intent is None or intent.status is not IntentStatus.OPEN:
            return None
        intent.status = IntentStatus.RUNNING
        return intent

    def settle(self, attack_id: str, status: IntentStatus, reason: str = "") -> None:
        intent = self.intents.get(attack_id)
        if intent is None:
            return
        intent.status = status
        intent.reason = reason

    def drop_category(self, category: str, reason: str) -> list[int]:
        """Give up on every unsettled intent in a category; returns dropped ids."""
        dropped = []
        for attack_id, intent in self.intents.items():
            if intent.category == category and not intent.settled:
                intent.status = IntentStatus.DROPPED
                intent.reason = reason
                dropped.append(attack_id)
        return dropped

    def open_intents(self) -> list[Intent]:
        return [i for i in self.intents.values() if not i.settled]

    def all_settled(self) -> bool:
        return not self.open_intents()

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in IntentStatus}
        for intent in self.intents.values():
            counts[intent.status.value] += 1
        counts["total"] = len(self.intents)
        return counts
