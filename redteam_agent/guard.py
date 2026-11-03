"""Guard: pre/post probe hooks plus an attributable audit trail.

ARTEX (`guard/guard.go`) gates every tool call through a hook registry, writes
an ``AuditEntry`` for each decision, and classifies tool results into
``ok | blocked | error`` so the planner learns the difference between "the
target refused" and "a WAF blocked us". The Python harness probes a target
directly, so the same three pieces map onto one probe:

* a pre-probe gate that refuses work it has already sent or cannot afford;
* a post-probe classifier that separates target-side defense from harness error;
* a bounded audit trail with a digest of the payload, never the payload itself.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

# ARTEX's Observer pattern (guard/guard.go:152): a reply that names a defensive
# ceiling is "blocked", not "clean". 403 and 429 are the same signal from a
# proxy, so one pattern covers both.
BLOCKED_PATTERN = re.compile(
    r"(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied|not\s+allowed)\b"
)

_AUDIT_LIMIT = 2000


def digest(*parts: str) -> str:
    blob = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class AuditEntry:
    """One gated probe decision. Mirrors ARTEX guard.AuditEntry."""

    ts: float
    tool: str
    action: str            # allow | block
    reason: str = ""
    digest: str = ""       # payload digest, never the payload
    attack_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "tool": self.tool,
            "action": self.action,
            "reason": self.reason,
            "digest": self.digest,
            "attack_id": self.attack_id,
        }


@dataclass
class Guard:
    """Bounded audit trail and failure attribution for one run."""

    max_entries: int = _AUDIT_LIMIT
    audit: list[AuditEntry] = field(default_factory=list, repr=False)
    attributions: dict[str, int] = field(default_factory=lambda: {"ok": 0, "blocked": 0, "error": 0})
    _seen: set[str] = field(default_factory=set, repr=False)

    # -- pre-probe ------------------------------------------------------
    def pre_probe(
        self,
        *,
        attack_id: str,
        payload: str,
        mutation: str,
        budget_ok: bool = True,
    ) -> tuple[bool, str]:
        """Decide whether a probe may be sent. Blocks are recorded either way."""
        payload_digest = digest(attack_id, mutation, payload)
        if not budget_ok:
            self._record("probe", "block", "budget exhausted", payload_digest, attack_id)
            return False, "budget exhausted"
        if payload_digest in self._seen:
            self._record("probe", "block", "duplicate payload+mutation", payload_digest, attack_id)
            return False, "duplicate payload+mutation"
        self._seen.add(payload_digest)
        self._record("probe", "allow", "", payload_digest, attack_id)
        return True, ""

    # -- post-probe -----------------------------------------------------
    def post_probe(
        self,
        *,
        attack_id: str,
        payload: str,
        mutation: str,
        text: str = "",
        tool_calls: list[dict[str, Any]] | None = None,
        error: str | None = None,
        finding: bool = False,
    ) -> str:
        """Classify what came back and count it. Returns ok|blocked|error."""
        payload_digest = digest(attack_id, mutation, payload)
        if error:
            classification = "error"
        elif BLOCKED_PATTERN.search(text or ""):
            classification = "blocked"
        else:
            classification = "ok"
        self.attributions[classification] = self.attributions.get(classification, 0) + 1
        if classification == "blocked" and not finding:
            # A clean reply under a block-ish word is still a block for planning
            # purposes; a finding takes precedence because a leak escaped anyway.
            self._record("probe", "allow", "class=blocked", payload_digest, attack_id)
        return classification

    # -- introspection --------------------------------------------------
    def blocked(self) -> int:
        return sum(1 for e in self.audit if e.action == "block")

    def blocked_for(self, attack_id: str) -> int:
        """How many probes of this attack the pre-probe gate refused."""
        return sum(1 for e in self.audit if e.action == "block" and e.attack_id == attack_id)

    def snapshot(self) -> dict[str, Any]:
        return {
            "entries": len(self.audit),
            "blocks": self.blocked(),
            "attributions": dict(self.attributions),
            "recent_blocks": [
                {**e.to_dict()} for e in self.audit if e.action == "block"
            ][-5:],
        }

    # -- internal -------------------------------------------------------
    def _record(
        self,
        tool: str,
        action: str,
        reason: str,
        payload_digest: str,
        attack_id: str,
    ) -> None:
        self.audit.append(
            AuditEntry(
                ts=round(time.time(), 3),
                tool=tool,
                action=action,
                reason=reason,
                digest=payload_digest,
                attack_id=attack_id,
            )
        )
        if len(self.audit) > self.max_entries:
            del self.audit[: len(self.audit) - self.max_entries]
