"""Read-only policy: guarantees a red-team run cannot delete or change the target.

Two surfaces need different enforcement:

* **Host and web actions** are executed by this harness, so the policy inspects
  the command or HTTP request before dispatch. A host command must match a
  read-only allowlist and no deny pattern; a web request must be a read method on
  a non-destructive path.
* **LLM probes** are executed by the target, and the target may call a tool with
  attacker-chosen arguments. The policy refuses to send a payload whose stated
  success criterion is a state-changing tool call unless the operator explicitly
  enables ``allow_state_changing`` and the target declares a vendored/sandboxed
  tool scope. That keeps the default danger from "demonstrate excessive agency"
  turning into "delete the customer table".

Nothing here replaces authorization; it is the non-destructive guarantee the
operator can tell their security team.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    """What an action does to the target."""

    READ = "read"          # no state change; allowed by default
    STATE = "state"        # target state could change
    DESTROY = "destroy"    # data or service destruction


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    effect: Effect = Effect.READ
    audit_notes: str = ""


# Commands that never change state. Anchored type prefixes, not free text.
_READ_PREFIXES = (
    "get-",
    "test-",
    "measure-",
    "select-",
    "resolve-",
    "format-",
)
_READ_ROOTS = (
    "systeminfo",
    "whoami",
    "hostname",
    "ipconfig",
    "route",
    "arp",
    "netstat",
    "ss",
    "ip ",
    "ps ",
    "top -b -n1",
    "lsof",
    "sw_vers",
    "uname",
    "systemsetup -get",
    "csrutil",
    "fdesetup status",
    "spctl --status",
    "socketfilterfw --get",
    "defaults read",
    "dscl . -read",
    "dscacheutil -q",
    "grep",
    "awk",
    "sed -n",
    "cut",
    "head",
    "tail",
    "wc ",
    "stat ",
    "ls ",
    "find ",
    "cat ",
    "sudo -l",
    "sudo -n",
    "systemctl is-active",
    "systemctl status",
    "systemctl list-units",
    "nft list",
    "iptables -l",
    "ufw status",
    "lastlog",
    "last "
    "getenforce",
    "/usr/libexec/applicationfirewall/socketfilterfw",
    "journalctl",
    "auditctl -l",
    "dpkg -l",
    "rpm -q",
    "apt list",
    "brew outdated",
    "brew list",
    "net view",
    "netsh advfirewall show",
    "netsh wlan show",
    "net accounts",
    "dscl . -list",
    "sc query",
    "schtasks /query",
    "wmic",
    "get-ciminstance",
)
# Normalize roots that start with a command and a fixed first token.
_READ_PATTERNS = (
    r"(?:^|[;&|(\s])(get|test|measure|select|resolve|format)-[a-z]",
    r"^\s*(net\s+(view|accounts|share|session|use)|netsh\s+(advfirewall|wlan|interface)\s+(show|dump))",
    r"^\s*sc\s+query",
    r"^\s*schtasks\s+/query",
    r"^\s*wmic\s+\w+\s+(get|list)",
    r"^\s*systeminfo",
)

_DESTROY_PATTERNS = (
    r"\b(rm|rmdir|del|erase|unlink)\b",
    r"\bremove-item\b",
    r"\b(delete-item|clear-content|clear-|stop-process|kill|taskkill)\b",
    r"\b(set-item|new-item|rename-item|move-item|copy-item)\b",
    r"\b(reg\s+(add|delete)|bcdedit|diskpart|format|mkfs|fdisk|dd\s+if=)\b",
    r"\b(shutdown|reboot|restart-computer|stop-computer|logoff)\b",
    r"\b(chmod|chown|chattr|setfacl)\b",
    r"(?:^|[;&|]\s*)(?:sudo\s+)?(useradd|usermod|userdel|groupadd|passwd(?=\s+[-\w]))\b",
    r"\bnet\s+user\s+\S+\s+/[a-z]+"
    r"\b(sc\s+(create|delete|config)|launchctl\s+(load|unload|bootstrap|bootout))\b",
    r"\b(defaults\s+write|dscl\s+\.\s+-(create|delete|passwd))\b",
    r"\b(tee|>>?)\s*/(etc|var|usr|bin|sbin|boot|opt|home)\b",
    r"\b(systemctl\s+(start|stop|restart|enable|disable|mask))\b",
    r"\b(pip|npm|apt|brew|yum|dnf)\s+(install|remove|uninstall|upgrade)\b",
)
_DESTROY_RE = re.compile("|".join(_DESTROY_PATTERNS), re.I)
# Output redirection except to /dev/null: writing a file changes the target.
_REDIRECT_RE = re.compile(r"(?<!2)>>?\s*(?!/dev/null)\S+|\btee\s+(?!/dev/null)\S+")

# Web paths whose side effect is a state change.
_WEB_DESTRUCTIVE_PATH = re.compile(
    r"/(delete|remove|destroy|reset|drop|truncate|create|update|edit|write|upload|import|restore|reboot|shutdown)(/|$|\?)",
    re.I,
)

# Tool names in the LLM attack library that change state if the target calls them.
STATE_CHANGING_TOOLS = frozenset(
    {
        "delete",
        "delete_account",
        "delete_audit_log",
        "delete_user",
        "export",
        "crm_export",
        "send",
        "send_email",
        "upload",
        "post",
        "create",
        "update",
        "write",
        "remove",
        "reset",
        "insert",
        "grant",
    }
)


def tool_effect(tool_prefix: str) -> Effect:
    needle = tool_prefix.lower()
    for name in STATE_CHANGING_TOOLS:
        if needle.startswith(name) or name.startswith(needle):
            return Effect.STATE
    return Effect.READ


@dataclass
class PolicyEngine:
    """Stateless decision function plus an audit hook."""

    allow_state_changing: bool = False
    audit: list[dict[str, Any]] = field(default_factory=list, repr=False)

    # -- host commands --------------------------------------------------
    def check_command(self, command: str) -> Decision:
        cmd = (command or "").strip()
        if not cmd:
            return Decision(False, "empty command", Effect.READ)
        if _DESTROY_RE.search(cmd):
            return self._blocked("command matches a destructive pattern", cmd, Effect.DESTROY)
        if _REDIRECT_RE.search(cmd):
            return self._blocked("command redirects output to a file, which changes the target", cmd, Effect.STATE)
        read = any(re.search(pattern, cmd, re.I) for pattern in _READ_PATTERNS)
        if not read:
            head = cmd.split()[0].lower() if cmd.split() else ""
            root_ok = any(cmd.lower().startswith(root) or f" {root}" in cmd.lower() for root in _READ_ROOTS)
            if not root_ok:
                return self._blocked(
                    "command is not in the read-only allowlist (prefix it with Get-/query/show)",
                    cmd,
                    Effect.STATE,
                )
        return Decision(True, effect=Effect.READ)

    # -- web requests ---------------------------------------------------
    def check_web(self, method: str, url: str, *, follow_redirects: bool = False) -> Decision:
        verb = (method or "GET").upper()
        if verb not in {"GET", "HEAD", "OPTIONS"}:
            return self._blocked(f"HTTP {verb} would change state; only GET/HEAD/OPTIONS are allowed", url, Effect.STATE)
        if _WEB_DESTRUCTIVE_PATH.search(url or ""):
            return self._blocked("URL path names a state-changing action", url, Effect.DESTROY)
        if follow_redirects:
            return self._blocked("redirect following would re-send credentials to another host", url, Effect.READ)
        return Decision(True, effect=Effect.READ)

    # -- LLM payloads ---------------------------------------------------
    def check_attack_effect(self, tool_prefixes: tuple[str, ...]) -> Decision:
        """A probe whose prize is a mutating tool is disallowed by default."""
        if self.allow_state_changing:
            return Decision(True, "state-changing probes enabled by operator", Effect.STATE)
        for prefix in tool_prefixes or ():
            if tool_effect(prefix) is Effect.STATE:
                return Decision(
                    False,
                    f"attack targets tool {prefix!r} which changes target state; "
                    "run with --allow-state-changing after sandboxing the tool scope",
                    Effect.STATE,
                )
        return Decision(True, effect=Effect.READ)

    # -- audit ----------------------------------------------------------
    def _blocked(self, reason: str, subject: str, effect: Effect) -> Decision:
        self.audit.append(
            {"effect": effect.value, "allowed": False, "reason": reason, "subject": subject[:160]}
        )
        return Decision(False, reason, effect)

    def snapshot(self) -> dict[str, Any]:
        return {
            "entries": len(self.audit),
            "blocks": sum(1 for a in self.audit if not a["allowed"]),
            "blocked_subjects": [a["subject"] for a in self.audit if not a["allowed"]][-10:],
            "allow_state_changing": self.allow_state_changing,
        }
