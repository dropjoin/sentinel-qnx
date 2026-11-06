"""Command line entry point: sentinel audit <path...>"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .rules import audit_files


def load(paths: list[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    files[str(f)] = f.read_text(errors="replace")
        else:
            files[str(path)] = path.read_text(errors="replace")
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="audit QNX buildfiles/scripts/manifests")
    a.add_argument("paths", nargs="+")
    a.add_argument("--json", action="store_true",
                   help="emit findings as JSON")
    r = sub.add_parser("report", help="audit plus narrative impact report")
    r.add_argument("paths", nargs="+")
    fx = sub.add_parser("fix", help="write auto-fixed copies, then re-audit")
    fx.add_argument("paths", nargs="+")
    fx.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "fix":
        from .fix import fix_files
        before = audit_files(load(args.paths))
        written = fix_files(load(args.paths), args.out)
        after = audit_files(written)
        print(f"fix: {len(before)} finding(s) before, "
              f"{len(after)} after. Fixed files in {args.out}/")
        for f in after:
            print(f"  remaining [{f.severity}] {f.rule_id} {f.file}:{f.line}"
                  " (needs a human decision)")
        bad = sum(1 for f in after if f.severity in ("CRITICAL", "HIGH"))
        return 1 if bad else 0

    findings = audit_files(load(args.paths))
    if args.cmd == "audit" and getattr(args, "json", False):
        import dataclasses
        import json as _json
        print(_json.dumps([dataclasses.asdict(f) for f in findings],
                          indent=2))
        bad = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
        return 1 if bad else 0
    if args.cmd == "report":
        from .explain import narrative
        print(narrative(findings))
        bad = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
        return 1 if bad else 0
    if not findings:
        print("Sentinel: no findings. Image configuration looks clean.")
        return 0
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"[{f.severity}] {f.rule_id} {loc}")
        print(f"  {f.title}")
        print(f"  Why: {f.explanation}")
        print(f"  Fix: {f.patch}")
    bad = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
    print(f"\n{len(findings)} finding(s), {bad} critical/high.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
