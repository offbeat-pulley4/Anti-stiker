"""Anti-Stiker CLI.

  python -m antistiker scan <file-or-dir> [--json]
  python -m antistiker sanitize <in.tgs> <out.tgs>
  python -m antistiker guard [--dir PATH ...] [--quarantine-dir PATH] [--once]
"""

from __future__ import annotations

import argparse
import json as jsonlib
import logging
import sys
from pathlib import Path

from . import __version__
from .paths import default_watch_dirs
from .tgs_scan import Verdict, iter_tgs_files, scan_file
from .sanitize import sanitize_file
from .watcher import Guard


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    results = [scan_file(p) for p in iter_tgs_files(target)]
    if not results:
        print(f"no .tgs files found under {target}", file=sys.stderr)
        return 2

    worst = Verdict.SAFE
    for result in results:
        worst = max(worst, result.verdict)
        if args.json:
            print(jsonlib.dumps({
                "file": result.file,
                "verdict": result.verdict.name,
                "findings": [
                    {"verdict": f.verdict.name, "code": f.code,
                     "message": f.message, "path": f.path}
                    for f in result.findings
                ],
            }))
        else:
            print(f"{result.verdict.name:10} {result.file}")
            for f in result.findings:
                print(f"           - [{f.code}] {f.message} ({f.path})")

    return 1 if worst != Verdict.SAFE else 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    try:
        sanitize_file(args.src, args.dst)
    except Exception as exc:  # noqa: BLE001 - surface any decode error to the user
        print(f"could not sanitize {args.src}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote sanitized copy to {args.dst}")
    return 0


def cmd_guard(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    watch_dirs = [Path(d) for d in args.dir] if args.dir else default_watch_dirs()
    if not watch_dirs:
        print("no watch directories found/specified; pass --dir explicitly", file=sys.stderr)
        return 2
    quarantine_dir = Path(args.quarantine_dir) if args.quarantine_dir else Path.home() / ".antistiker" / "quarantine"
    guard = Guard(watch_dirs, quarantine_dir, poll_interval=args.interval,
                  quarantine_suspicious=args.quarantine_suspicious)
    if args.once:
        n = guard.scan_once(report_unchanged=True)
        print(f"quarantined {n} file(s)")
        return 0
    guard.run_forever()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="antistiker", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a .tgs file or a directory of them")
    p_scan.add_argument("target", help="file or directory to scan")
    p_scan.add_argument("--json", action="store_true", help="emit JSON lines")
    p_scan.set_defaults(func=cmd_scan)

    p_san = sub.add_parser("sanitize", help="write a repaired copy of a flagged .tgs")
    p_san.add_argument("src")
    p_san.add_argument("dst")
    p_san.set_defaults(func=cmd_sanitize)

    p_guard = sub.add_parser("guard", help="watch directories and quarantine kill-stickers")
    p_guard.add_argument("--dir", action="append", help="directory to watch (repeatable)")
    p_guard.add_argument("--quarantine-dir", help="where to move flagged files")
    p_guard.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds")
    p_guard.add_argument("--quarantine-suspicious", action="store_true",
                          help="also quarantine SUSPICIOUS (not just MALICIOUS) files")
    p_guard.add_argument("--once", action="store_true", help="scan once and exit instead of looping")
    p_guard.set_defaults(func=cmd_guard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
