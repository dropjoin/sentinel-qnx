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
    p = perms.strip().lstrip("0")
    if p.isdigit() and len(p) >= 3:
        return int(p[-1]) & 2 == 2
    return "o+w" in perms or "a+w" in perms or "a=rwx" in perms
