"""Read-only Windows endpoint audit through PowerShell.

Every script is passed to ``PolicyEngine.check_command`` first; the allowlist
accepts Get-/Test-/query-style cmdlets and the deny list rejects Set-/New-/Remove-
and any output redirection. The audit never writes, installs, restarts or deletes.

Severity follows CIS Windows 10 benchmarks; the categories map to the ``CIS-WIN10``
section names in ``taxonomy``.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

from ..policy import PolicyEngine
from .model import SurfaceFinding, error_result, info_result, pass_result

FRAMEWORK = "CIS-WIN10"


@dataclass
class PSResult:
    script: str
    ok: bool = False
    stdout: str = ""
    stderr: str = ""
    blocked: bool = False
    reason: str = ""
    elapsed_ms: float = 0.0


def _json_lines(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            out.append(value)
        elif isinstance(value, list):
            out.extend(v for v in value if isinstance(v, dict))
    return out


class WindowsAuditor:
    def __init__(self, policy: PolicyEngine | None = None, timeout_s: float = 90.0) -> None:
        self.policy = policy or PolicyEngine()
        self.timeout_s = timeout_s
        self.results: list[PSResult] = []

    def _ps(self, script: str) -> PSResult:
        decision = self.policy.check_command(script)
        if not decision.allowed:
            return PSResult(script=script, blocked=True, reason=decision.reason)
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command",
                    "$ErrorActionPreference='Stop'; " + script,
                ],
                capture_output=True, text=True, timeout=self.timeout_s,
            )
            res = PSResult(script=script, ok=proc.returncode == 0, stdout=proc.stdout, stderr=proc.stderr)
        except (subprocess.TimeoutExpired, OSError) as exc:
            res = PSResult(script=script, stderr=f"{type(exc).__name__}: {exc}")
        res.elapsed_ms = (time.perf_counter() - started) * 1000
        self.results.append(res)
        return res

    def _json(self, script: str) -> list[dict]:
        res = self._ps(script)
        if res.blocked:
            return []
        return _json_lines(res.stdout) or _json_lines(res.stderr)

    # -- platform -------------------------------------------------------
    def check_platform(self) -> SurfaceFinding:
        rows = self._json(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate | ConvertTo-Json -Compress"
        )
        if not rows:
            return error_result("WIN.PLATFORM", "Windows platform identification", FRAMEWORK, "W1", "localhost", "Win32_OperatingSystem query failed")
        row = rows[0]
        caption = str(row.get("Caption") or row.get("caption") or "Windows")
        build = str(row.get("BuildNumber") or row.get("buildnumber") or "")
        return info_result(
            "WIN.PLATFORM", "Windows platform identified", FRAMEWORK, "W1", "localhost",
            f"{caption}; build {build}; {row.get('OSArchitecture') or ''}".strip(),
        )

    # -- defenses -------------------------------------------------------
    def check_defender(self) -> list[SurfaceFinding]:
        row = self._json("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge,AntivirusSignatureLastUpdated,AMServiceEnabled | ConvertTo-Json -Compress")
        if not row:
            return [error_result("WIN.DEFENDER", "Microsoft Defender status", FRAMEWORK, "W9", "localhost", "Get-MpComputerStatus failed (Defender may be absent or replaced)")]
        r = row[0]
        out: list[SurfaceFinding] = []
        if not r.get("RealTimeProtectionEnabled") and not r.get("AMServiceEnabled"):
            out.append(SurfaceFinding(
                check_id="WIN.DEFENDER.disabled", title="Real-time malware protection is disabled", framework=FRAMEWORK,
                category="W9", severity="high", target="localhost",
                evidence=f"RealTimeProtectionEnabled={r.get('RealTimeProtectionEnabled')} AMServiceEnabled={r.get('AMServiceEnabled')}",
                remediation="Re-enable Defender and reconcile any third-party EDR policy",
                reproduction="Get-MpComputerStatus | Select RealTimeProtectionEnabled,AMServiceEnabled", confidence=0.9,
            ))
        age = r.get("AntivirusSignatureAge")
        if isinstance(age, (int, float)) and age > 7:
            out.append(SurfaceFinding(
                check_id="WIN.DEFENDER.signatures", title="Antivirus signatures are stale", framework=FRAMEWORK,
                category="W9", severity="medium", target="localhost",
                evidence=f"signature age {age} days; last {r.get('AntivirusSignatureLastUpdated')}",
                remediation="Fix the update source so signatures refresh automatically",
                reproduction="Get-MpComputerStatus | Select AntivirusSignatureAge", confidence=0.85,
            ))
        return out or [pass_result("WIN.DEFENDER", "Defender real-time protection and signatures look healthy", FRAMEWORK, "W9", "localhost", f"signature age {age}")]

    def check_firewall(self) -> list[SurfaceFinding]:
        rows = self._json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
        disabled = [r for r in rows if r.get("Enabled") in (False, 0)]
        if disabled:
            names = ", ".join(str(r.get("Name")) for r in disabled)
            return [SurfaceFinding(
                check_id="WIN.FIREWALL.disabled", title="Firewall profiles are disabled", framework=FRAMEWORK,
                category="W12", severity="high", target="localhost",
                evidence=f"disabled profiles: {names}",
                remediation="Enable all profiles; keep inbound default deny",
                reproduction="Get-NetFirewallProfile | Select Name,Enabled", confidence=0.95,
            )]
        return [pass_result("WIN.FIREWALL", "All firewall profiles are enabled", FRAMEWORK, "W12", "localhost", f"{len(rows)} profiles")]

    # -- legacy protocols ---------------------------------------------
    def check_legacy_protocols(self) -> list[SurfaceFinding]:
        smb1 = self._json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json -Compress")
        out: list[SurfaceFinding] = []
        if smb1 and smb1[0].get("EnableSMB1Protocol") in (True, 1):
            out.append(SurfaceFinding(
                check_id="WIN.SMB.v1", title="SMBv1 is enabled", framework=FRAMEWORK,
                category="W12", severity="high", target="localhost",
                evidence="EnableSMB1Protocol=True", remediation="Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) after inventory",
                reproduction="Get-SmbServerConfiguration | Select EnableSMB1Protocol", confidence=0.95,
                manual_review=True,
            ))
        lanman = self._json("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select-Object LmCompatibilityLevel | ConvertTo-Json -Compress")
        if lanman:
            level = lanman[0].get("LmCompatibilityLevel")
            if isinstance(level, int) and level < 3:
                out.append(SurfaceFinding(
                    check_id="WIN.LANMAN", title="NTLM LAN manager compatibility permits weak responses", framework=FRAMEWORK,
                    category="W4", severity="medium", target="localhost",
                    evidence=f"LmCompatibilityLevel={level} (Windows 10 baseline is 5)", remediation="Set LmCompatibilityLevel to 5",
                    reproduction="Get-ItemProperty 'HKLM:\\SYSTEM\\...\\Lsa' | Select LmCompatibilityLevel", confidence=0.8,
                ))
        llmnr = self._json("Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -ErrorAction SilentlyContinue | Select-Object EnableMulticast | ConvertTo-Json -Compress")
        if llmnr and llmnr[0].get("EnableMulticast") in (1, True):
            out.append(SurfaceFinding(
                check_id="WIN.LLMNR.enabled", title="LLMNR multicast resolution is enabled", framework=FRAMEWORK,
                category="W12", severity="low", target="localhost",
                evidence="EnableMulticast=1", remediation="Disable LLMNR via GPO (EnableMulticast=0)",
                reproduction="Get-ItemProperty HKLM:\\...\\DNSClient | Select EnableMulticast", confidence=0.8, manual_review=True,
            ))
        return out or [pass_result("WIN.LEGACY", "No SMBv1, weak LAN manager level or LLMNR enabled", FRAMEWORK, "W12", "localhost")]

    # -- remote access --------------------------------------------------
    def check_remote_access(self) -> list[SurfaceFinding]:
        out: list[SurfaceFinding] = []
        rdp = self._json("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TerminalServer\\WinStations\\RDP-Tcp' | Select-Object UserAuthentication,PortNumber | ConvertTo-Json -Compress")
        rdp_svc = self._ps("Get-Service TermService -ErrorAction SilentlyContinue | Select-Object Status,StartType | ConvertTo-Json -Compress")
        if rdp:
            if rdp[0].get("UserAuthentication") in (0, False):
                out.append(SurfaceFinding(
                    check_id="WIN.RDP.nla", title="RDP does not require Network Level Authentication", framework=FRAMEWORK,
                    category="W4", severity="high", target="localhost",
                    evidence=f"UserAuthentication=0 port={rdp[0].get('PortNumber')}", remediation="Require NLA for all RDP endpoints",
                    reproduction="Get-ItemProperty 'HKLM:\\...\\RDP-Tcp' | Select UserAuthentication", confidence=0.9,
                ))
            port = rdp[0].get("PortNumber")
            if isinstance(port, int) and port not in (3389,):
                out.append(info_result("WIN.RDP.port", "RDP listens on a non-default port", FRAMEWORK, "W12", "localhost", f"port {port}", "Port shifting is not a control; keep NLA and account lockout"))
        if rdp_svc:
            rows = _json_lines(rdp_svc.stdout) or _json_lines(rdp_svc.stderr)
            if rows and rows[0].get("Status") in ("Running",):
                out.append(info_result("WIN.RDP.service", "Terminal Services is running", FRAMEWORK, "W12", "localhost", f"StartType={rows[0].get('StartType')}"))
        winrm = self._json("Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Status,StartType | ConvertTo-Json -Compress")
        if winrm and winrm[0].get("Status") in ("Running",):
            out.append(SurfaceFinding(
                check_id="WIN.WINRM.running", title="WinRM is running", framework=FRAMEWORK,
                category="W12", severity="medium", target="localhost",
                evidence=f"StartType={winrm[0].get('StartType')}", remediation="Restrict WinRM to management VLANs or disable it",
                reproduction="Get-Service WinRM | Select Status,StartType", confidence=0.85, manual_review=True,
            ))
        return out or [pass_result("WIN.REMOTE", "No obvious weak remote-access exposure", FRAMEWORK, "W12", "localhost")]

    # -- privilege ------------------------------------------------------
    def check_privilege(self) -> list[SurfaceFinding]:
        out: list[SurfaceFinding] = []
        uac = self._json("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin | ConvertTo-Json -Compress")
        if uac and uac[0].get("EnableLUA") in (0, False):
            out.append(SurfaceFinding(
                check_id="WIN.UAC.disabled", title="User Account Control is disabled", framework=FRAMEWORK,
                category="W4", severity="high", target="localhost",
                evidence=f"EnableLUA={uac[0].get('EnableLUA')}", remediation="Re-enable UAC and admin approval mode",
                reproduction="Get-ItemProperty 'HKLM:\\...\\Policies\\System' | Select EnableLUA", confidence=0.95,
            ))
        admins = self._json("Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue | Select-Object Name,PrincipalSource | ConvertTo-Json -Compress")
        names = [str(r.get("Name")) for r in admins]
        if len(names) > 3:
            out.append(SurfaceFinding(
                check_id="WIN.ADMINS.broad", title="Local Administrators group is broad", framework=FRAMEWORK,
                category="W4", severity="medium", target="localhost",
                evidence=f"{len(names)} members: {', '.join(names[:10])}", remediation="Trim to break-glass and named admins",
                reproduction="Get-LocalGroupMember Administrators", confidence=0.8, manual_review=True,
            ))
        shares = self._json("Get-SmbShare | Select-Object Name,Path | ConvertTo-Json -Compress")
        admin_shares = [r for r in shares if str(r.get("Name", "")).endswith("$") and str(r.get("Name", "")).startswith(("C", "ADMIN", "IPC"))]
        if admin_shares:
            out.append(info_result("WIN.SMB.adminshares", "Default administrative shares are present", FRAMEWORK, "W12", "localhost", ", ".join(str(r.get('Name')) for r in admin_shares[:5]), "Control access; they are administrative by design"))
        return out or [pass_result("WIN.PRIVILEGE", "UAC on and Administrators group not obviously broad", FRAMEWORK, "W4", "localhost")]

    def check_service_paths(self) -> list[SurfaceFinding]:
        """Unquoted service paths and service binaries in user-writable trees.

        Both are classic local privilege-escalation conditions; proving them needs
        a safe read-only query, not a write into the service directory.
        """
        rows = self._json(
            "Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName | ConvertTo-Json -Compress"
        )
        protected = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                     "\\program files\\", "\\program files (x86)\\")
        unquoted = []
        for row in rows:
            path = str(row.get("PathName") or "")
            if not path or path.startswith('"') or " " not in path:
                continue
            exe = path.split(" ")[0]
            if not exe.lower().endswith(".exe"):
                continue
            # Unquoted is only a weakness when the executable sits in a tree an
            # unprivileged user could rewrite. svchost.exe under system32 is
            # unquoted by design and not exploitable.
            if any(protected in exe.lower() for protected in protected):
                continue
            unquoted.append(str(row.get("Name")))
        if unquoted:
            return [SurfaceFinding(
                check_id="WIN.SERVICES.unquoted", title="Services with unquoted executable paths", framework=FRAMEWORK,
                category="W4", severity="high", target="localhost",
                evidence=f"{len(unquoted)} service(s): {', '.join(unquoted[:8])}",
                remediation="Quote the service binary path; audit the parent directories for writability",
                reproduction="Get-CimInstance Win32_Service | Where-Object {$_.PathName -notmatch '^\"'}", confidence=0.85,
                manual_review=True,
            )]
        risky_dirs = ('\\programdata\\', '\\users\\', '\\temp\\', '\\appdata\\')
        user_writable = [
            str(row.get("Name")) for row in rows
            if any(d in str(row.get("PathName") or "").lower() for d in risky_dirs)
        ]
        if user_writable:
            return [SurfaceFinding(
                check_id="WIN.SERVICES.userwritable", title="Service binaries live in user-writable trees", framework=FRAMEWORK,
                category="W4", severity="medium", target="localhost",
                evidence=f"{len(user_writable)} service(s): {', '.join(user_writable[:8])}",
                remediation="Move binaries to a protected Program Files path and restrict directory ACLs",
                reproduction="Get-CimInstance Win32_Service | Where-Object {$_.PathName -match 'ProgramData|Users'}", confidence=0.8,
                manual_review=True,
            )]
        return [pass_result("WIN.SERVICES", "No unquoted or user-writable service path sampled", FRAMEWORK, "W4", "localhost", f"{len(rows)} services")]

    def check_weak_accounts(self) -> list[SurfaceFinding]:
        users = self._json(
            "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet | ConvertTo-Json -Compress"
        )
        no_password = [str(u.get("Name")) for u in users if u.get("Enabled") and u.get("PasswordRequired") in (False, 0)]
        builtin = [str(u.get("Name")) for u in users if str(u.get("Name")).lower() in ("guest", "defaultaccount")]
        out: list[SurfaceFinding] = []
        if no_password:
            out.append(SurfaceFinding(
                check_id="WIN.USERS.nopassword", title="Enabled accounts do not require a password", framework=FRAMEWORK,
                category="W4", severity="high", target="localhost",
                evidence=f"{len(no_password)} account(s): {', '.join(no_password[:8])}",
                remediation="Require a password (or disable) for these accounts",
                reproduction="Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false}", confidence=0.95,
            ))
        if builtin:
            out.append(info_result("WIN.USERS.builtin", "Default accounts are present", FRAMEWORK, "W4", "localhost", ", ".join(builtin[:4]), "Keep guest disabled"))
        return out or [pass_result("WIN.USERS", "Local accounts require passwords", FRAMEWORK, "W4", "localhost", f"{len(users)} accounts")]

    def check_network_listeners(self) -> list[SurfaceFinding]:
        rows = self._json(
            "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
        )
        exposed = [str(r) for r in rows if str(r.get("LocalAddress")) in ("0.0.0.0", "::", "*")]
        ports = sorted({r.get("LocalPort") for r in rows if r.get("LocalPort") is not None})
        if exposed:
            return [SurfaceFinding(
                check_id="WIN.PORTS.exposed", title="Services listen on all interfaces", framework=FRAMEWORK,
                category="W12", severity="medium", target="localhost",
                evidence=f"{len(exposed)} listener(s) on 0.0.0.0/::; ports {ports[:20]}",
                remediation="Bind management services to loopback and firewall the rest",
                reproduction="Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort", confidence=0.8,
            )]
        return [pass_result("WIN.PORTS", "No all-interface TCP listeners", FRAMEWORK, "W12", "localhost", f"{len(ports)} ports")]

    def check_autoruns(self) -> SurfaceFinding:
        rows = self._json(
            r"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ConvertTo-Json -Compress"
        )
        entries = 0
        samples: list[str] = []
        if rows:
            for row in rows:
                for key, value in row.items():
                    if key.lower() in ("pspath", "psparentpath", "pschildname", "psdrive", "psprovider"):
                        continue
                    if isinstance(value, str) and value.strip():
                        entries += 1
                        if len(samples) < 5:
                            samples.append(f"{key}={value[:60]}")
        if entries > 12:
            return [SurfaceFinding(
                check_id="WIN.AUTORUN.broad", title="Large startup program surface", framework=FRAMEWORK,
                category="W2", severity="info", target="localhost",
                evidence=f"{entries} Run registry values; e.g. {', '.join(samples)}",
                remediation="Review startup entries against the approved baseline",
                reproduction=r"Get-ItemProperty 'HKLM:\...\Run'", confidence=0.5, manual_review=True,
            )]
        return info_result("WIN.AUTORUN", "Startup entries sampled", FRAMEWORK, "W2", "localhost", f"{entries} entries")

    def check_smb_signing(self) -> list[SurfaceFinding]:
        rows = self._json("Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature,EncryptData | ConvertTo-Json -Compress")
        if not rows:
            return [error_result("WIN.SMB.signing", "SMB signing state", FRAMEWORK, "W12", "localhost", "query failed")]
        r = rows[0]
        if not r.get("RequireSecuritySignature"):
            return [SurfaceFinding(
                check_id="WIN.SMB.signing", title="SMB signing is not required", framework=FRAMEWORK,
                category="W12", severity="medium", target="localhost",
                evidence=f"RequireSecuritySignature={r.get('RequireSecuritySignature')} EncryptData={r.get('EncryptData')}",
                remediation="Require SMB signing on all server and client configurations",
                reproduction="Get-SmbServerConfiguration | Select RequireSecuritySignature", confidence=0.85,
            )]
        return [pass_result("WIN.SMB.signing", "SMB signing is required", FRAMEWORK, "W12", "localhost", f"EncryptData={r.get('EncryptData')}")]

    def check_patches(self) -> SurfaceFinding:
        rows = self._json("Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID,InstalledOn | Sort-Object InstalledOn -Descending | ConvertTo-Json -Compress")
        dates = []
        for r in rows:
            value = r.get("InstalledOn")
            if value:
                dates.append(str(value))
        if not dates:
            return error_result("WIN.PATCH", "Patch identification", FRAMEWORK, "W2", "localhost", "Get-HotFix returned nothing (Windows Update may be managed elsewhere)")
        return info_result("WIN.PATCH", "Patch history sampled", FRAMEWORK, "W2", "localhost", f"{len(rows)} hotfixes; latest {dates[0]}", "Verify the cumulative update baseline through Windows Update, not just hotfixes")

    def run(self) -> list[SurfaceFinding]:
        out = [self.check_platform(), self.check_patches()]
        out.extend(self.check_defender())
        out.extend(self.check_firewall())
        out.extend(self.check_legacy_protocols())
        out.extend(self.check_remote_access())
        out.extend(self.check_privilege())
        out.extend(self.check_service_paths())
        out.extend(self.check_weak_accounts())
        out.extend(self.check_network_listeners())
        out.append(self.check_autoruns())
        out.extend(self.check_smb_signing())
        return out
