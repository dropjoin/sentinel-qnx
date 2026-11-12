"""Command line entry point: sentinel audit <path...>"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .rules import audit_files

# Config files are kilobytes; a directory walk must not swallow a
# multi-gigabyte disk image into memory. Oversized files are skipped
# with a warning, never read.
MAX_FILE_BYTES = 10 * 1024 * 1024


def _add(files: dict[str, str], seen: set[str], path: Path,
         strict: bool) -> None:
    """Read one file into files, unless it was already loaded.

    Paths are deduplicated by resolved location, so the same file
    given twice (relative and absolute spellings, overlapping
    directory and file arguments) is audited once. Unreadable files
    fail hard when named explicitly (strict) and warn-and-skip when
    found during a directory walk.
    """
    try:
        key = str(path.resolve())
    except OSError:
        key = str(path)
    if key in seen:
        return
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"sentinel: warning: skipping {path} "
                  f"(larger than {MAX_FILE_BYTES} bytes)", file=sys.stderr)
            seen.add(key)
            return
        text = path.read_text(errors="replace")
    except OSError:
        if strict:
            raise
        print(f"sentinel: warning: cannot read {path}, skipping",
              file=sys.stderr)
        seen.add(key)
        return
    seen.add(key)
    files[str(path)] = text


def load(paths: list[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    seen: set[str] = set()
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    _add(files, seen, f, strict=False)
        else:
            _add(files, seen, path, strict=True)
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

    try:
        files = load(args.paths)
    except OSError as e:
        print(f"sentinel: error: {e}", file=sys.stderr)
        return 2
    if not files:
        print("sentinel: error: no files to audit", file=sys.stderr)
        return 2

    if args.cmd == "fix":
        from .fix import fix_files
        before = audit_files(files)
        written = fix_files(files, args.out)
        after = audit_files(written)
        print(f"fix: {len(before)} finding(s) before, "
              f"{len(after)} after. Fixed files in {args.out}/")
        for f in after:
            print(f"  remaining [{f.severity}] {f.rule_id} {f.file}:{f.line}"
                  " (needs a human decision)")
        bad = sum(1 for f in after if f.severity in ("CRITICAL", "HIGH"))
        return 1 if bad else 0

    findings = audit_files(files)
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
