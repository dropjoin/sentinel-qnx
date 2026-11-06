"""Sentinel for QNX - deterministic audit rules (v0).

Each rule scans QNX buildfiles, startup scripts and image manifests for
production-unsafe configurations. Findings carry severity, file, line, a
plain-English explanation and a suggested patch. The AI explanation layer
sits on top of these findings; the rules themselves never guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    file: str
    line: int
    title: str
    explanation: str
    patch: str


# Small bundled database of components with well-known CVE classes.
# Versions are matched as prefixes; the full DB ships with the tool.
VULN_COMPONENTS = [
    ("openssl", "1.0.", "CRITICAL",
     "OpenSSL 1.0.x is end-of-life and carries the Heartbleed class of "
     "memory-disclosure bugs (CVE-2014-0160 and follow-ups)."),
    ("openssl", "1.1.0", "HIGH",
     "OpenSSL 1.1.0 is end-of-life; upgrade to a maintained 3.x line."),
    ("busybox", "1.2", "HIGH",
     "BusyBox 1.2x is far behind upstream security fixes for its applets."),
    ("dropbear", "2016", "HIGH",
     "Dropbear 2016-era builds miss years of SSH server hardening."),
    ("zlib", "1.2.5", "MEDIUM",
     "zlib 1.2.5 predates the CVE-2022-37434 inflate fix."),
]

SHELL_ON_CONSOLE = re.compile(
    r"\b(on|spawn|reopen)\b[^\n]*\b(sh|ksh|esh)\b", re.IGNORECASE)
TELNET_FTP = re.compile(r"^\s*(telnet|ftp|tftp)\b[^\n]*\binetd\b|"
                        r"\binetd\b[^\n]*\b(telnetd|ftpd)\b", re.IGNORECASE)
PERMISSIVE = re.compile(r"\bchmod\s+(-R\s+)?(777|666|a\+rwx)\b|\bumask\s+0+\b")
VERSION_LINE = re.compile(r"^([A-Za-z0-9_.+-]+)[\s:=]+v?(\d+\.\d+(?:\.\d+)?)\s*$")
APS_MARKER = re.compile(r"\b(aps|SCHED_APS|adaptive\s+partition)", re.IGNORECASE)


def audit_text(file: str, text: str, whole_set_has_aps: bool) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if SHELL_ON_CONSOLE.search(line):
            findings.append(Finding(
                "DEBUG_SHELL", "CRITICAL", file, i,
                "Interactive shell spawned on a console",
                "A root shell on a serial or virtual console gives anyone "
                "with physical or emulator access full control of the "
                "device. Shipping images must not spawn interactive "
                "shells outside a debug build.",
                "Remove the shell spawn from the production startup "
                "script, or guard it behind a debug-only build variant."))
        if TELNET_FTP.search(line):
            findings.append(Finding(
                "CLEARTEXT_SERVICE", "HIGH", file, i,
                "Cleartext remote service enabled (telnet/ftp)",
                "Telnet and FTP send credentials in cleartext and are a "
                "standing entry point on embedded targets. Use SSH-based "
                "access or disable remote login in production images.",
                "Remove the inetd telnet/ftp entries; ship sshd only, "
                "with key-based auth."))
        if PERMISSIVE.search(line):
            findings.append(Finding(
                "PERMISSIVE_MODE", "HIGH", file, i,
                "World-writable permission set in startup script",
                "chmod 777/666 or umask 000 makes binaries, configs or "
                "device nodes writable by every user and process, which "
                "defeats QNX's privilege separation.",
                "Set the least-privilege mode the owner process needs "
                "(typically 755 for binaries, 644 for data) and a "
                "restrictive umask such as 022."))
        m = VERSION_LINE.match(line)
        if m:
            name, ver = m.group(1).lower(), m.group(2)
            for comp, prefix, sev, why in VULN_COMPONENTS:
                if name == comp and ver.startswith(prefix):
                    findings.append(Finding(
                        "VULN_COMPONENT", sev, file, i,
                        f"Vulnerable bundled component: {comp} {ver}",
                        why,
                        f"Upgrade {comp} to a maintained release and "
                        "rebuild the image; re-run the audit to confirm "
                        "the new version is bundled."))
    return findings


def audit_files(files: dict[str, str]) -> list[Finding]:
    """Audit a set of {filename: text}. Adds set-level findings."""
    has_aps = any(APS_MARKER.search(t) for t in files.values())
    out: list[Finding] = []
    for name, text in files.items():
        out.extend(audit_text(name, text, has_aps))
        if name.endswith(".build"):
            out.extend(audit_buildfile(name, text))
        if "sshd" in name.lower():
            out.extend(audit_sshd(name, text))
        base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in ("passwd", "shadow", "master.passwd"):
            out.extend(audit_passwd(name, text))
    if files and not has_aps:
        out.append(Finding(
            "NO_ADAPTIVE_PARTITIONING", "MEDIUM", "(image set)", 0,
            "No adaptive partitioning configuration found",
            "Without QNX adaptive partitioning, a runaway or compromised "
            "process can starve safety-critical threads of CPU. Partition "
            "budgets are the standard QNX mechanism for guaranteeing "
            "minimum CPU shares to critical work.",
            "Define an APS configuration with guaranteed budgets for "
            "the safety-critical partitions and a scheduler policy for "
            "the rest."))
    out.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                             "LOW": 3}[f.severity], f.file, f.line))
    return out


def audit_buildfile(file: str, text: str) -> list[Finding]:
    """Rules that need parsed buildfile structure, not raw text."""
    from .buildfile import parse_buildfile, world_writable

    out: list[Finding] = []
    for e in parse_buildfile(text):
        perms = e.attrs.get("perms", "")
        if perms and world_writable(perms):
            out.append(Finding(
                "WORLD_WRITABLE_FILE", "HIGH", file, e.line,
                f"Shipped file is world-writable: {e.target}",
                "A file baked into the image with world-writable "
                "permissions can be modified by any process or user on "
                "the running system, including unprivileged ones. For "
                "binaries and configs this is a straight privilege "
                "escalation path.",
                f"Ship {e.target} with least-privilege perms "
                "(755 for executables, 644 for data) in the buildfile "
                "attribute block."))
    return out


SSHD_SETTING = re.compile(
    r"^\s*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|"
    r"Protocol|X11Forwarding)\s+(\S+)", re.IGNORECASE)
SSHD_BAD = {
    "permitrootlogin": ("yes", "CRITICAL",
                        "SSH root login is enabled",
                        "PermitRootLogin yes lets anyone password-guess "
                        "straight into the most privileged account on the "
                        "device. Embedded targets ship with known or "
                        "shared root credentials far too often.",
                        "Set PermitRootLogin no (or prohibit-password "
                        "with key-only admin access)."),
    "passwordauthentication": ("yes", "HIGH",
                               "SSH password authentication is enabled",
                               "Password auth on an embedded SSH server "
                               "invites brute force against default or "
                               "weak device passwords.",
                               "Set PasswordAuthentication no and ship "
                               "per-device keys."),
    "permitemptypasswords": ("yes", "CRITICAL",
                             "SSH empty passwords are permitted",
                             "PermitEmptyPasswords yes means accounts "
                             "with no password can log in remotely.",
                             "Set PermitEmptyPasswords no and audit "
                             "every account in the image's passwd file."),
    "x11forwarding": ("yes", "LOW",
                      "SSH X11 forwarding is enabled",
                      "X11 forwarding is rarely needed on an embedded "
                      "target and widens the SSH attack surface.",
                      "Set X11Forwarding no in the production sshd_config."),
}


def audit_sshd(file: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        m = SSHD_SETTING.match(raw)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).lower()
        spec = SSHD_BAD.get(key)
        if spec and val == spec[0]:
            out.append(Finding("SSHD_" + key.upper(), spec[1], file, i,
                               spec[2], spec[3], spec[4]))
        if key == "protocol" and val.startswith("1"):
            out.append(Finding(
                "SSHD_PROTOCOL1", "HIGH", file, i,
                "SSH protocol 1 is enabled",
                "SSH protocol 1 has known cryptographic weaknesses and "
                "has been removed from maintained OpenSSH for years.",
                "Remove the Protocol line or set Protocol 2."))
    return out


PASSWD_LINE = re.compile(r"^([a-z_][a-z0-9_-]*):([^:]*):(\d+):", re.IGNORECASE)


def audit_passwd(file: str, text: str) -> list[Finding]:
    """Account-file checks: empty password fields, uid 0 accounts."""
    out: list[Finding] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        m = PASSWD_LINE.match(raw.strip())
        if not m:
            continue
        user, pw, uid = m.group(1), m.group(2), m.group(3)
        if pw == "":
            out.append(Finding(
                "EMPTY_PASSWORD", "CRITICAL", file, i,
                f"Account '{user}' has an empty password field",
                "An account with an empty password field can be logged "
                "into with no credential at all wherever a login prompt "
                "reaches it (console, SSH, ftp). Sample and BSP account "
                "files ship like this surprisingly often.",
                "Set a real password hash or lock the account "
                "('*' / '!') if it never logs in interactively."))
        if uid == "0" and user != "root":
            out.append(Finding(
                "EXTRA_UID0", "HIGH", file, i,
                f"Non-root account '{user}' has uid 0",
                "A second uid-0 account is a classic backdoor and audit "
                "blind spot: every action it takes is attributed to "
                "root.",
                "Remove the account or give it a unique non-zero uid "
                "with only the privileges it needs."))
    return out
