"""Narrative layer: turns findings into an auditor's report.

The explanations are authored per rule family: an impact scenario (how
the flaw is exploited on a real embedded target) and the remediation
order. The report is complete and deterministic without any model;
every rule id the auditor can emit has an entry in IMPACT below.
"""
from __future__ import annotations

from .rules import Finding

IMPACT = {
    "DEBUG_SHELL": "An attacker with serial or emulator console access "
                   "boots the device and lands in a root shell before "
                   "any application starts. No credentials, no exploit "
                   "chain, just a cable.",
    "CLEARTEXT_SERVICE": "Anyone on the same network segment can sniff "
                         "or hijack telnet/FTP sessions and harvest the "
                         "credentials technicians use in the field.",
    "PERMISSIVE_MODE": "A low-privilege process rewrites a config or "
                       "binary that a privileged service later loads, "
                       "turning a minor foothold into full control.",
    "WORLD_WRITABLE_FILE": "The writable file ships in every unit. One "
                           "unprivileged app bug is enough to persist "
                           "malicious changes across reboots.",
    "VULN_COMPONENT": "The bundled library's known vulnerability class "
                      "is reachable from the device's network surface; "
                      "public exploits for EOL components are a search "
                      "away.",
    "NO_ADAPTIVE_PARTITIONING": "A single runaway process can saturate "
                                "the CPU and starve the safety loop. On "
                                "a medical or automotive target that is "
                                "a safety incident, not a performance "
                                "bug.",
    "SSHD_PERMITROOTLOGIN": "Anyone who guesses or leaks the root "
                            "password lands straight in the most "
                            "privileged account over the network, with "
                            "no second account to slow them down.",
    "SSHD_PASSWORDAUTHENTICATION": "Password logins invite automated "
                                   "brute force against the default or "
                                   "weak passwords embedded targets "
                                   "so often ship with.",
    "SSHD_PERMITEMPTYPASSWORDS": "Any account left without a password "
                                 "can be opened remotely with no "
                                 "credential at all.",
    "SSHD_X11FORWARDING": "An attacker with an SSH session can abuse "
                          "the forwarded X channel to snoop or inject "
                          "input on a display the device was never "
                          "meant to expose.",
    "SSHD_PROTOCOL1": "Protocol 1 sessions can be decrypted and "
                       "hijacked with decades-old attacks; a device "
                       "that still negotiates it hands the network "
                       "everything SSH was meant to protect.",
    "EMPTY_PASSWORD": "An account with no password is an open door "
                      "wherever a login prompt reaches it: console, "
                      "SSH, or FTP. No exploit needed.",
    "EXTRA_UID0": "A second uid-0 account is a ready-made backdoor "
                  "whose actions are indistinguishable from root's, "
                  "so misuse leaves no accountable trail.",
}


def narrative(findings: list[Finding]) -> str:
    if not findings:
        return "Executive summary: no findings. The image configuration " \
               "passes every Sentinel check in this run."
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    head = ", ".join(f"{counts[s]} {s.lower()}" for s in
                     ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in counts)
    lines = [f"Executive summary: {len(findings)} finding(s): {head}. "
             "Remediation order follows severity; fix critical and high "
             "before this image ships.", ""]
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{f.severity}] {f.title} ({loc})")
        impact = IMPACT.get(f.rule_id)
        if impact:
            lines.append(f"  Impact scenario: {impact}")
        lines.append(f"  Fix: {f.patch}")
    return "\n".join(lines)
