"""Conservative auto-fix: rewrite the flaws that have a safe mechanical
repair, into an output directory, and leave everything else untouched.

Auto-fixable: console shell spawns (commented out), inetd cleartext
lines (commented out), chmod 777/666 -> 755, umask 000 -> 022, and
buildfile perms with the others-write bit cleared. Component upgrades
and APS design are human decisions and are never auto-applied.
"""
from __future__ import annotations

import re
from pathlib import Path

from .rules import PERMISSIVE, SHELL_ON_CONSOLE, TELNET_FTP

CHMOD_FIX = re.compile(r"\bchmod\s+(-R\s+)?(777|666|a\+rwx)\b")
UMASK_FIX = re.compile(r"\bumask\s+0+\b")
PERMS_FIX = re.compile(r"(perms=)(0?[0-7]{3,4})")


def _fix_perms_value(v: str) -> str:
    digits = v.lstrip("0") or "0"
    if len(digits) < 3:
        return v
    others = int(digits[-1]) & ~2
    group = int(digits[-2]) & ~2 if digits[-2].isdigit() else 0
    return "0" + digits[-3] + str(group) + str(others) if len(digits) == 3 \
        else "0" + digits[-3] + str(group) + str(others)


def fix_text(name: str, text: str) -> str:
    out_lines = []
    for raw in text.splitlines():
        line = raw
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if SHELL_ON_CONSOLE.search(stripped) or \
                    TELNET_FTP.search(stripped):
                line = "# SENTINEL-FIX disabled: " + stripped
            else:
                line = CHMOD_FIX.sub(lambda m: "chmod " +
                                     (m.group(1) or "") + "755", line)
                line = UMASK_FIX.sub("umask 022", line)
                if name.endswith(".build"):
                    line = PERMS_FIX.sub(
                        lambda m: m.group(1) + _fix_perms_value(m.group(2)),
                        line)
        out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def fix_files(files: dict[str, str], out_dir: str) -> dict[str, str]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    for name, text in files.items():
        fixed = fix_text(name, text)
        target = dest / Path(name).name
        target.write_text(fixed)
        written[str(target)] = fixed
    return written
