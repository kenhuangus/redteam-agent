"""Read-only macOS endpoint audit over SSH (or locally on Darwin).

Every command goes through ``PolicyEngine.check_command``. The auditor only reads
versions, security settings and listening sockets; it never changes FileVault, SIP,
the firewall or any account.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field

from ..policy import PolicyEngine
from .model import SurfaceFinding, error_result, info_result, pass_result

FRAMEWORK = "CIS-MACOS"


@dataclass
class MacCommand:
    command: str
    ok: bool = False
    stdout: str = ""
    stderr: str = ""
    blocked: bool = False
    reason: str = ""
    elapsed_ms: float = 0.0


@dataclass
class MacOSAuditor:
    ssh_target: str = ""
    timeout_s: float = 30.0
    policy: PolicyEngine = field(default_factory=PolicyEngine)

    def _run(self, command: str) -> MacCommand:
        decision = self.policy.check_command(command)
        if not decision.allowed:
            return MacCommand(command=command, blocked=True, reason=decision.reason)
        started = time.perf_counter()
        argv = (
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", self.ssh_target, command]
            if self.ssh_target else ["/bin/sh", "-c", command]
        )
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout_s)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return MacCommand(command=command, stderr=f"{type(exc).__name__}: {exc}",
                              elapsed_ms=(time.perf_counter() - started) * 1000)
        return MacCommand(command=command, ok=proc.returncode == 0, stdout=proc.stdout,
                          stderr=proc.stderr, elapsed_ms=(time.perf_counter() - started) * 1000)

    def _target(self) -> str:
        return self.ssh_target or "this-mac"

    def check_platform(self) -> SurfaceFinding:
        res = self._run("sw_vers")
        if res.blocked:
            return error_result("MAC.PLATFORM", "macOS platform identification", FRAMEWORK, "M1", self._target(), res.reason)
        data = dict(line.split(":", 1) for line in res.stdout.splitlines() if ":" in line)
        version = data.get("ProductVersion", "unknown").strip()
        build = data.get("BuildVersion", "").strip()
        model = self._run("uname -m").stdout.strip()
        return info_result("MAC.PLATFORM", "macOS platform identified", FRAMEWORK, "M1", self._target(),
                           f"macOS {version} ({build}) arch {model}")

    def check_integrity(self) -> list[SurfaceFinding]:
        out: list[SurfaceFinding] = []
        sip = self._run("csrutil status").stdout
        if "disabled" in sip.lower():
            out.append(SurfaceFinding(
                check_id="MAC.SIP.disabled", title="System Integrity Protection is disabled", framework=FRAMEWORK,
                category="M2", severity="critical", target=self._target(),
                evidence=sip.strip()[:160], remediation="Re-enable SIP from Recovery (csrutil enable) — this is a maintenance action",
                reproduction="csrutil status", confidence=0.98,
            ))
        gate = self._run("spctl --status").stdout
        if "disabled" in gate.lower():
            out.append(SurfaceFinding(
                check_id="MAC.GATEKEEPER.disabled", title="Gatekeeper is disabled", framework=FRAMEWORK,
                category="M2", severity="high", target=self._target(),
                evidence=gate.strip()[:160], remediation="Enable app assessment (spctl --enable)",
                reproduction="spctl --status", confidence=0.95,
            ))
        return out or [pass_result("MAC.INTEGRITY", "SIP and Gatekeeper are enabled", FRAMEWORK, "M2", self._target(), f"{sip.strip()}/{gate.strip()}")]

    def check_encryption(self) -> list[SurfaceFinding]:
        fv = self._run("fdesetup status").stdout.strip()
        if "On" in fv or "Enabled" in fv:
            return [pass_result("MAC.ENCRYPTION", "FileVault is on", FRAMEWORK, "M3", self._target(), fv[:120])]
        return [SurfaceFinding(
            check_id="MAC.ENCRYPTION.filevault", title="FileVault is not enabled", framework=FRAMEWORK,
            category="M3", severity="high", target=self._target(),
            evidence=fv[:160] or "fdesetup returned no status", remediation="Enable FileVault in policy before the next failed audit",
            reproduction="fdesetup status", confidence=0.85 if fv else 0.6, manual_review=True,
        )]

    def check_firewall(self) -> SurfaceFinding:
        res = self._run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
        text = res.stdout.strip()
        if "disabled" in text.lower():
            return SurfaceFinding(
                check_id="MAC.FIREWALL.disabled", title="Application firewall is disabled", framework=FRAMEWORK,
                category="M12", severity="medium", target=self._target(),
                evidence=text[:160], remediation="Enable the firewall unless an approved SASE/EDR layer replaces it",
                reproduction="socketfilterfw --getglobalstate", confidence=0.9,
            )
        return pass_result("MAC.FIREWALL", "Application firewall is on", FRAMEWORK, "M12", self._target(), text[:120] or "no state string")

    def check_ssh(self) -> list[SurfaceFinding]:
        res = self._run(
            "grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|"
            "ChallengeResponseAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null"
        )
        settings = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                settings[parts[0].lower()] = parts[1].lower()
        out: list[SurfaceFinding] = []
        if settings.get("permitrootlogin") == "yes":
            out.append(SurfaceFinding(
                check_id="MAC.SSH.rootlogin", title="SSH permits root login", framework=FRAMEWORK,
                category="M4", severity="high", target=self._target(),
                evidence="PermitRootLogin yes", remediation="Set PermitRootLogin prohibit-password",
                reproduction="grep -i PermitRootLogin /etc/ssh/sshd_config", confidence=0.95,
            ))
        if settings.get("passwordauthentication") == "yes":
            out.append(SurfaceFinding(
                check_id="MAC.SSH.passwordauth", title="SSH accepts passwords", framework=FRAMEWORK,
                category="M4", severity="medium", target=self._target(),
                evidence="PasswordAuthentication yes", remediation="Disable password authentication and require keys",
                reproduction="grep -i PasswordAuthentication /etc/ssh/sshd_config", confidence=0.9,
            ))
        return out or [pass_result("MAC.SSH", "sshd has no obvious weak authentication setting", FRAMEWORK, "M4", self._target(), f"{len(settings)} directives read")]

    def check_sudo(self) -> SurfaceFinding:
        res = self._run("grep -h NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null")
        lines = [l.strip() for l in res.stdout.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#")]
        if lines:
            return SurfaceFinding(
                check_id="MAC.SUDO.nopasswd", title="Passwordless sudo is granted", framework=FRAMEWORK,
                category="M4", severity="high", target=self._target(),
                evidence=f"{len(lines)} entries; first: {lines[0][:160]}", remediation="Scope sudo rules and require authentication",
                reproduction="sudo -l", confidence=0.9, manual_review=True,
            )
        return pass_result("MAC.SUDO", "No passwordless sudo entries", FRAMEWORK, "M4", self._target())

    def check_listening(self) -> list[SurfaceFinding]:
        res = self._run("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null")
        lines = [l for l in res.stdout.splitlines()[1:] if l.strip()]
        exposed = [l for l in lines if "0.0.0.0:" in l or "[::]:" in l or " *:" in l]
        if exposed:
            ports = []
            for line in exposed:
                for token in line.split():
                    if token.endswith("(LISTEN)") or token.rsplit(":", 1)[-1].isdigit():
                        ports.append(token)
            return [SurfaceFinding(
                check_id="MAC.NET.exposed", title="Services listen on all interfaces", framework=FRAMEWORK,
                category="M12", severity="medium", target=self._target(),
                evidence=f"{len(exposed)} listeners: " + "; ".join(exposed[:6])[:600],
                remediation="Bind developer servers to localhost and firewall the rest",
                reproduction="lsof -nP -iTCP -sTCP:LISTEN", confidence=0.8,
            )]
        return [pass_result("MAC.NET", "No obvious all-interface listeners in lsof output", FRAMEWORK, "M12", self._target(), f"{len(lines)} sockets")]

    def check_login_settings(self) -> list[SurfaceFinding]:
        out: list[SurfaceFinding] = []
        auto = self._run("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null").stdout.strip()
        if auto and auto.lower() not in ("does not exist",):
            out.append(SurfaceFinding(
                check_id="MAC.LOGIN.autologin", title="Automatic login is configured", framework=FRAMEWORK,
                category="M5", severity="high", target=self._target(),
                evidence=f"autoLoginUser={auto[:40]}", remediation="Disable automatic login so FileVault can gate boot",
                reproduction="defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser", confidence=0.8,
                manual_review=True,
            ))
        guest = self._run("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null").stdout.strip()
        if guest in ("1", "true", "TRUE"):
            out.append(SurfaceFinding(
                check_id="MAC.LOGIN.guest", title="Guest account is enabled", framework=FRAMEWORK,
                category="M5", severity="medium", target=self._target(),
                evidence="GuestEnabled=1", remediation="Disable the guest user",
                reproduction="defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled", confidence=0.9,
            ))
        res = self._run("systemsetup -getrequirespassword 2>/dev/null")
        text = res.stdout.strip()
        if "Off" in text:
            out.append(SurfaceFinding(
                check_id="MAC.LOGIN.screensaver", title="Password is not required after sleep", framework=FRAMEWORK,
                category="M5", severity="medium", target=self._target(),
                evidence=text[:120], remediation="Require a password immediately after sleep and screensaver",
                reproduction="systemsetup -getrequirespassword", confidence=0.8, manual_review=True,
            ))
        return out or [pass_result("MAC.LOGIN", "Login settings carry no obvious weakness", FRAMEWORK, "M5", self._target())]

    def check_updates(self) -> SurfaceFinding:
        res = self._run("brew outdated 2>/dev/null")
        lines = [l for l in res.stdout.splitlines() if l.strip()]
        if len(lines) > 15:
            return SurfaceFinding(
                check_id="MAC.UPDATES.brew", title="Large number of outdated brew packages", framework=FRAMEWORK,
                category="M2", severity="low", target=self._target(),
                evidence=f"{len(lines)} outdated; first: {lines[0][:120]}", remediation="Fold brew upgrades into the patch window",
                reproduction="brew outdated", confidence=0.7,
            )
        return pass_result("MAC.UPDATES", "brew package drift is low or brew absent", FRAMEWORK, "M2", self._target(), f"{len(lines)} outdated")

    def run(self) -> list[SurfaceFinding]:
        out = [self.check_platform()]
        out.extend(self.check_integrity())
        out.extend(self.check_encryption())
        out.append(self.check_firewall())
        out.extend(self.check_ssh())
        out.append(self.check_sudo())
        out.extend(self.check_listening())
        out.extend(self.check_login_settings())
        out.append(self.check_updates())
        return out
