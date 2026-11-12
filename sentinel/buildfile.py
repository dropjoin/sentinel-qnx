"""Minimal QNX buildfile (mkifs) parser.

Extracts entries with their attribute blocks so rules can reason about
what actually ships in the image: target path, host source, and
attributes such as perms/uid/gid.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

ATTR_BLOCK = re.compile(r"\[([^\]]*)\]")
ASSIGN = re.compile(r"^([^\s=\[]+)\s*=\s*(.+)$")


@dataclass
class Entry:
    target: str
    source: str | None
    attrs: dict[str, str] = field(default_factory=dict)
    line: int = 0


def parse_attrs(block: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    block = block.strip()
    if block.startswith("+") or block.startswith("image"):
        return attrs
    for part in re.split(r"[\s,]+", block):
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip()] = v.strip()
    return attrs


def parse_buildfile(text: str) -> list[Entry]:
    entries: list[Entry] = []
    pending: dict[str, str] = {}
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ATTR_BLOCK.match(line)
        if m and (line.startswith("[+") or "=" in m.group(1) or
                  m.group(1).startswith("image")):
            pending.update(parse_attrs(m.group(1)))
            line = line[m.end():].strip()
            if not line:
                continue
        am = ASSIGN.match(line)
        if am:
            entries.append(Entry(am.group(1), am.group(2), dict(pending), i))
        elif not line.startswith("["):
            entries.append(Entry(line.split()[0], None, dict(pending), i))
        pending = {}
    return entries


def world_writable(perms: str) -> bool:
    """True when an octal or symbolic perms value grants others-write."""
    return mode_grants_world_write(perms)


_OCTAL_MODE = re.compile(r"[0-7]+")
_SYMBOLIC_CLAUSE = re.compile(r"([ugoa]*)([+\-=])([rwxXstugo]*)")


def mode_grants_world_write(mode: str) -> bool:
    """True when a chmod/buildfile mode grants write to 'others'.

    Octal modes are evaluated numerically, so leading zeros (0777),
    short modes (77, 7) and setuid/setgid/sticky modes (4777) are all
    handled. Symbolic modes are evaluated clause by clause: a clause
    grants others-write when it targets 'o'/'a' (or no class, which
    means all) with '+'/'=' and includes 'w'. Clauses that remove
    write ('o-w') or omit it ('o=r') do not.
    """
    m = mode.strip().split(";", 1)[0]
    if _OCTAL_MODE.fullmatch(m):
        return int(m, 8) & 0o002 != 0
    for clause in m.split(","):
        cm = _SYMBOLIC_CLAUSE.fullmatch(clause)
        if cm is None:
            continue
        who, op, perms = cm.groups()
        if (op in ("+", "=") and "w" in perms
                and ("o" in who or "a" in who or not who)):
            return True
    return False


def fixed_octal_mode(mode: str) -> str:
    """Octal mode with group/other write bits cleared, special bits kept.

    '0777' -> '0755', '666' -> '644', '4777' -> '4755'. The result
    keeps the input's digit width (minimum 3). Raises ValueError on
    non-octal input; callers must validate first.
    """
    cleared = int(mode, 8) & ~0o022
    return format(cleared, "0%do" % max(3, len(mode)))
