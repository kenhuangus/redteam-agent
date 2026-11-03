"""Read-only Linux endpoint audit.

Commands run either locally (Darwin rejects the Linux probes and the auditor says
so) or over an SSH connection to a user-authorized host. Every command passes
``PolicyEngine.check_command`` before it is dispatched; a command that would write,
install, restart or delete anything is never sent to the target.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field

from ..policy import PolicyEngine
from .model import SurfaceFinding, error_result, info_result, pass_result

FRAMEWORK = "CIS-LINUX"


@dataclass
class CommandResult:
    command: str
    ok: bool = False
    stdout: str = ""
    stderr: str = ""
    blocked: bool = False
    reason: str = ""
    elapsed_ms: float = 0.0


@dataclass
class LinuxAuditor:
    """Audit one Linux host, locally or through SSH, read-only."""

    ssh_target: str = ""
    timeout_s: float = 30.0
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    results: list[CommandResult] = field(default_factory=list)
    local_os: str = ""

    def _run(self, command: str) -> CommandResult:
        decision = self.policy.check_command(command)
        if not decision.allowed:
            return CommandResult(command=command, blocked=True, reason=decision.reason)
        started = time.perf_counter()
        argvs: list[list[str]]
        if self.ssh_target:
            argvs = [["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", self.ssh_target, command]]
        else:
            argvs = [["/bin/sh", "-c", command]]
        for argv in argvs:
            try:
                proc = subprocess.run(
                    argv, capture_output=True, text=True, timeout=self.timeout_s,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                res = CommandResult(command=command, stderr=f"{type(exc).__name__}: {exc}")
            else:
                res = CommandResult(
                    command=command,
                    ok=proc.returncode == 0,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )
            res.elapsed_ms = (time.perf_counter() - started) * 1000
            self.results.append(res)
            return res
        raise RuntimeError("unreachable")

    # -- identity -------------------------------------------------------
    def check_platform(self) -> SurfaceFinding:
        res = self._run("cat /etc/os-release")
        if res.blocked:
            return error_result("LNX.PLATFORM", "Linux platform identification", FRAMEWORK, "L1", self._target(), res.reason)
        if "Darwin" in res.stderr or "No such file" in res.stderr:
            return error_result("LNX.PLATFORM", "Linux platform identification", FRAMEWORK, "L1", self._target(), "not Linux (os-release absent)")
        fields = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip().strip('"')
        name = fields.get("PRETTY_NAME") or fields.get("ID") or "unknown"
        kernel = self._run("uname -r").stdout.strip()
        return info_result("LNX.PLATFORM", "Linux platform identified", FRAMEWORK, "L1", self._target(), f"{name}; kernel {kernel}")

    # -- SSH ------------------------------------------------------------
    def check_ssh(self) -> list[SurfaceFinding]:
        res = self._run(
            "grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|"
            "X11Forwarding|PermitUserEnvironment)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null"
        )
        if not res.ok and not res.stdout:
            return [error_result("LNX.SSH", "OpenSSH configuration", FRAMEWORK, "L4", self._target(), res.stderr or "sshd_config unreadable")]
        out = []
        settings = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                settings[parts[0].lower()] = parts[1].lower()
        ssh_active = self._run("systemctl is-active sshd").stdout.strip() or self._run("systemctl is-active ssh").stdout.strip()
        if "yes" == settings.get("permitrootlogin"):
            out.append(SurfaceFinding(
                check_id="LNX.SSH.rootlogin", title="SSH permits root password login", framework=FRAMEWORK,
                category="L4", severity="high", target=self._target(),
                evidence=f"PermitRootLogin yes (sshd {ssh_active or 'status unknown'})",
                remediation="Set PermitRootLogin prohibit-password and use key-based admin access",
                reproduction="grep -i PermitRootLogin /etc/ssh/sshd_config", confidence=0.95,
            ))
        if "yes" == settings.get("passwordauthentication"):
            out.append(SurfaceFinding(
                check_id="LNX.SSH.passwordlogin", title="SSH accepts passwords", framework=FRAMEWORK,
                category="L4", severity="medium", target=self._target(),
                evidence="PasswordAuthentication yes",
                remediation="Disable password authentication and enforce keys or MFA",
                reproduction="grep -i PasswordAuthentication /etc/ssh/sshd_config", confidence=0.9,
            ))
        if "yes" == settings.get("permitemptypasswords"):
            out.append(SurfaceFinding(
                check_id="LNX.SSH.emptypassword", title="SSH accepts empty passwords", framework=FRAMEWORK,
                category="L4", severity="critical", target=self._target(),
                evidence="PermitEmptyPasswords yes",
                remediation="Set PermitEmptyPasswords no; remove accounts without passwords",
                reproduction="grep -i PermitEmptyPasswords /etc/ssh/sshd_config", confidence=0.98,
            ))
        if "yes" == settings.get("x11forwarding"):
            out.append(SurfaceFinding(
                check_id="LNX.SSH.x11", title="SSH X11 forwarding enabled", framework=FRAMEWORK,
                category="L12", severity="low", target=self._target(),
                evidence="X11Forwarding yes",
                remediation="Disable X11 forwarding (X11Forwarding no) unless required",
                reproduction="grep -i X11Forwarding /etc/ssh/sshd_config", confidence=0.85,
            ))
        return out or [pass_result("LNX.SSH", "OpenSSH configuration has no obvious weakness", FRAMEWORK, "L4", self._target(), f"sshd {ssh_active}")]

    # -- accounts -------------------------------------------------------
    def check_accounts(self) -> list[SurfaceFinding]:
        zero = self._run("awk -F: '$3==0 {print $1}' /etc/passwd")
        names = [n.strip() for n in zero.stdout.splitlines() if n.strip()]
        extra = [n for n in names if n != "root"]
        out: list[SurfaceFinding] = []
        if extra:
            out.append(SurfaceFinding(
                check_id="LNX.ACCOUNTS.uid0", title="Additional UID 0 accounts present", framework=FRAMEWORK,
                category="L4", severity="critical", target=self._target(),
                evidence=f"uid 0 accounts: {', '.join(names[:10])}",
                remediation=f"Remove non-root UID 0 accounts ({', '.join(extra[:5])}) after confirming ownership",
                reproduction="awk -F: '$3==0 {print $1}' /etc/passwd", confidence=0.98,
            ))
        empty = self._run("awk -F: '$2==\"\" {print $1}' /etc/passwd")
        empties = [n.strip() for n in empty.stdout.splitlines() if n.strip()]
        empties = [n for n in empties if n not in ("*", "!")]
        if empties:
            out.append(SurfaceFinding(
                check_id="LNX.ACCOUNTS.empty", title="Accounts with empty password field", framework=FRAMEWORK,
                category="L4", severity="critical", target=self._target(),
                evidence=f"{len(empties)} accounts: {', '.join(empties[:10])}",
                remediation="Lock the accounts or set a strong password hash",
                reproduction='awk -F: \'$2=="" {print $1}\' /etc/passwd', confidence=0.95,
            ))
        sudo = self._run("grep -h NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null")
        lines = [l.strip() for l in sudo.stdout.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#")]
        if lines:
            out.append(SurfaceFinding(
                check_id="LNX.ACCOUNTS.nopasswd", title="Passwordless sudo rights granted", framework=FRAMEWORK,
                category="L4", severity="high", target=self._target(),
                evidence=f"{len(lines)} NOPASSWD entries; first: {lines[0][:160]}",
                remediation="Replace NOPASSWD with a targeted command allowlist that asks for a password",
                reproduction="sudo -l", confidence=0.9, manual_review=True,
            ))
        return out or [pass_result("LNX.ACCOUNTS", "No extra UID 0, empty-password or NOPASSWD accounts", FRAMEWORK, "L4", self._target())]

    # -- files ----------------------------------------------------------
    def check_files(self) -> list[SurfaceFinding]:
        world = self._run(
            "find /etc /usr/local /opt /home /var/tmp -xdev -type f -perm -0002 -not -name '.Xauthority' "
            "-not -name '*.log' -not -name '*.pid' 2>/dev/null | head -20"
        )
        files = [f for f in world.stdout.splitlines() if f.strip()]
        if files:
            return [SurfaceFinding(
                check_id="LNX.FILES.worldwritable", title="World-writable files in configuration and home trees",
                framework=FRAMEWORK, category="L6", severity="medium", target=self._target(),
                evidence=f"{len(files)} files; e.g. {', '.join(files[:5])}",
                remediation="Remove world-write permission (chmod o-w) and review why it was needed",
                reproduction="find /etc /home -xdev -type f -perm -0002 | head", confidence=0.85,
                manual_review=True,
            )]
        shadow = self._run("stat -c '%a %U %G %n' /etc/shadow /etc/passwd")
        if "shadow" in shadow.stdout and shadow.stdout.split()[0] not in ("640", "600", "000"):
            return [SurfaceFinding(
                check_id="LNX.FILES.shadow", title="Password file permissions are broader than 640",
                framework=FRAMEWORK, category="L4", severity="medium", target=self._target(),
                evidence=shadow.stdout.strip()[:200],
                remediation="chmod 640 /etc/shadow /etc/passwd and keep group root:shadow",
                reproduction="stat -c '%a %U %G %n' /etc/shadow", confidence=0.8,
            )]
        return [pass_result("LNX.FILES", "No world-writable config file and shadow is not broad", FRAMEWORK, "L6", self._target(), shadow.stdout.strip()[:160])]

    def _target(self) -> str:
        return self.ssh_target or "localhost"

    # -- network exposure ----------------------------------------------
    def check_listening(self) -> SurfaceFinding:
        res = self._run("ss -Hltun 2>/dev/null || netstat -tuln 2>/dev/null")
        if not res.ok and not res.stdout.strip():
            return error_result("LNX.NET", "Listening TCP/UDP services", FRAMEWORK, "L12", self._target(), res.stderr)
        exposed = []
        for line in res.stdout.splitlines():
            if "0.0.0.0:" in line or "[::]:" in line or "*:" in line:
                exposed.append(line.strip())
        if exposed:
            return SurfaceFinding(
                check_id="LNX.NET.exposed", title="Services bound to all interfaces", framework=FRAMEWORK,
                category="L12", severity="medium", target=self._target(),
                evidence=f"{len(exposed)} listeners: " + "; ".join(exposed[:8]),
                remediation="Bind management services to loopback or a private interface and firewall the rest",
                reproduction="ss -Hltun", confidence=0.8,
            )
        return pass_result("LNX.NET", "Listening services are loopback-only", FRAMEWORK, "L12", self._target(), res.stdout[:200])

    # -- patch, logging, cron, firewall --------------------------------
    def check_updates(self) -> SurfaceFinding:
        res = self._run(
            "apt list --upgradable 2>/dev/null || dnf check-update --quiet 2>/dev/null || "
            "zypper list-updates 2>/dev/null"
        )
        lines = [l for l in res.stdout.splitlines() if l.strip() and "Listing" not in l and "Upgradable" not in l]
        security = [l for l in lines if "security" in l.lower()]
        if security:
            return SurfaceFinding(
                check_id="LNX.UPDATES.security", title="Security updates are pending", framework=FRAMEWORK,
                category="L2", severity="medium", target=self._target(),
                evidence=f"{len(security)} security upgrades pending of {len(lines)} total; e.g. {security[0].strip()[:160]}",
                remediation="Patch on the maintenance window; confirm the CVEs before changing anything",
                reproduction="apt list --upgradable", confidence=0.8,
            )
        if len(lines) > 20:
            return SurfaceFinding(
                check_id="LNX.UPDATES.backlog", title="Large pending update backlog", framework=FRAMEWORK,
                category="L2", severity="low", target=self._target(),
                evidence=f"{len(lines)} packages upgradable", remediation="Bring the patch cadence back into policy",
                reproduction="apt list --upgradable", confidence=0.7,
            )
        return pass_result("LNX.UPDATES", "No obvious pending security updates", FRAMEWORK, "L2", self._target(), f"{len(lines)} upgradable")

    def check_audit(self) -> SurfaceFinding:
        state = self._run("systemctl is-active auditd").stdout.strip()
        enabled = self._run("systemctl is-enabled auditd").stdout.strip()
        if state and state not in ("active",) or enabled in ("disabled", "masked"):
            return SurfaceFinding(
                check_id="LNX.AUDIT.service", title="Audit service is not active", framework=FRAMEWORK,
                category="L8", severity="medium", target=self._target(),
                evidence=f"auditd state={state!r} enabled={enabled!r}",
                remediation="Enable auditd in policy; confirm with the platform owner before changing",
                reproduction="systemctl status auditd", confidence=0.8,
            )
        return pass_result("LNX.AUDIT", "Audit service active", FRAMEWORK, "L8", self._target(), state or "unknown")

    def check_cron(self) -> SurfaceFinding:
        res = self._run("ls -l /etc/cron.d /etc/cron.daily 2>/dev/null")
        if "No such file" in res.stderr and not res.stdout.strip():
            return info_result("LNX.CRON", "No cron directories", FRAMEWORK, "L8", self._target())
        return info_result("LNX.CRON", "Scheduled jobs are present", FRAMEWORK, "L8", self._target(), f"{len(res.stdout.splitlines())} entries", "Review ownership; a job writing to config trees is a persistence path")

    def check_firewall(self) -> SurfaceFinding:
        res = self._run("sudo -n ufw status 2>/dev/null || systemctl is-active firewalld 2>/dev/null")
        text = res.stdout.strip()
        if "inactive" in text or "Status: inactive" in text:
            return SurfaceFinding(
                check_id="LNX.FIREWALL.disabled", title="Host firewall is inactive", framework=FRAMEWORK,
                category="L12", severity="medium", target=self._target(),
                evidence=text[:160], remediation="Enable the host firewall or confirm network-level control",
                reproduction="sudo ufw status", confidence=0.85,
            )
        return pass_result("LNX.FIREWALL", "Host firewall does not appear disabled", FRAMEWORK, "L12", self._target(), text[:120] or "no ufw/firewalld output")

    def run(self) -> list[SurfaceFinding]:
        out: list[SurfaceFinding] = [self.check_platform()]
        out.extend(self.check_ssh())
        out.extend(self.check_accounts())
        out.extend(self.check_files())
        out.append(self.check_listening())
        out.append(self.check_updates())
        out.append(self.check_audit())
        out.append(self.check_cron())
        out.append(self.check_firewall())
        return out
