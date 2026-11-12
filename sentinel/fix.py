"""Conservative auto-fix: rewrite the flaws that have a safe mechanical
repair, into an output directory, and leave everything else untouched.

Auto-fixable: console shell spawns (commented out), inetd cleartext
lines (commented out), world-writable chmod modes (write bits
cleared: 777 -> 755, 666 -> 644, symbolic modes normalized to 755),
umask 000 -> 022, and buildfile perms with the group/other write bits
cleared (special bits kept: 4777 -> 4755). Component upgrades, sshd
settings, account changes and APS design are human decisions and are
never auto-applied.

Detection and repair share one definition of "world-writable" (see
sentinel.buildfile), so a mode the auditor flags is a mode the fixer
clears: fix output re-audits clean for every auto-fixable rule.
"""
from __future__ import annotations

import re
from pathlib import Path

from .buildfile import fixed_octal_mode, mode_grants_world_write
from .rules import CHMOD_CMD, SHELL_ON_CONSOLE, TELNET_FTP

UMASK_FIX = re.compile(r"\bumask\s+0+\b")
PERMS_FIX = re.compile(r"(perms=)([0-7]+)")
_OCTAL_TOKEN = re.compile(r"[0-7]+")


def _fix_perms_value(v: str) -> str:
    try:
        return fixed_octal_mode(v)
    except ValueError:
        return v


def _fix_chmod(m: re.Match) -> str:
    mode = m.group(2)
    if not mode_grants_world_write(mode):
        return m.group(0)
    core, sep, tail = mode.partition(";")
    if _OCTAL_TOKEN.fullmatch(core):
        fixed = fixed_octal_mode(core)
    else:
        fixed = "755"
    return "chmod " + m.group(1) + fixed + sep + tail


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
                line = CHMOD_CMD.sub(_fix_chmod, line)
                line = UMASK_FIX.sub("umask 022", line)
                if name.lower().endswith(".build"):
                    line = PERMS_FIX.sub(
                        lambda m: m.group(1) + _fix_perms_value(m.group(2)),
                        line)
        out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def _output_path(dest: Path, name: str) -> Path:
    """Mirror the input path under dest, without ever escaping it.

    Basename-only output silently overwrote one input when two inputs
    shared a basename; mirroring keeps every input distinct. Anchor,
    '.' and '..' components are dropped so a crafted name cannot
    write outside the output directory.
    """
    parts = [p for p in Path(name).parts if p not in ("/", ".", "..")]
    if not parts:
        parts = ["unnamed"]
    return dest.joinpath(*parts)


def fix_files(files: dict[str, str], out_dir: str) -> dict[str, str]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    for name, text in files.items():
        fixed = fix_text(name, text)
        target = _output_path(dest, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fixed)
        written[str(target)] = fixed
    return written
