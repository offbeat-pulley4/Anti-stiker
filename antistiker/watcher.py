"""Polling guard: watches one or more directories for .tgs files and
quarantines anything that scan_file() flags as MALICIOUS, before you get a
chance to drag it into AyuGram.

Stdlib-only (no external "watchdog" dependency) -- polls mtimes, which is
plenty fast enough for a handful of directories checked every couple of
seconds.
"""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Iterable

from .tgs_scan import Verdict, iter_tgs_files, scan_file

log = logging.getLogger("antistiker.watcher")


class Guard:
    def __init__(
        self,
        watch_dirs: Iterable[Path],
        quarantine_dir: Path,
        poll_interval: float = 2.0,
        quarantine_suspicious: bool = False,
    ) -> None:
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.quarantine_dir = Path(quarantine_dir)
        self.poll_interval = poll_interval
        self.quarantine_suspicious = quarantine_suspicious
        self._seen: dict[Path, float] = {}

    def _should_quarantine(self, verdict: Verdict) -> bool:
        if verdict == Verdict.MALICIOUS:
            return True
        return self.quarantine_suspicious and verdict == Verdict.SUSPICIOUS

    def scan_once(self, report_unchanged: bool = False) -> int:
        """Scan all watched directories right now. Returns number of files
        quarantined."""
        quarantined = 0
        for watch_dir in self.watch_dirs:
            if not watch_dir.exists():
                continue
            for path in iter_tgs_files(watch_dir):
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if self._seen.get(path) == mtime:
                    continue
                self._seen[path] = mtime

                result = scan_file(path)
                if self._should_quarantine(result.verdict):
                    self._quarantine(path, result)
                    quarantined += 1
                elif result.verdict == Verdict.SUSPICIOUS:
                    log.warning("SUSPICIOUS %s: %s", path,
                                "; ".join(f.message for f in result.findings))
                elif report_unchanged:
                    log.info("safe %s", path)
        return quarantined

    def _quarantine(self, path: Path, result) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self.quarantine_dir / path.name
        counter = 1
        while dest.exists():
            dest = self.quarantine_dir / f"{path.stem}.{counter}{path.suffix}"
            counter += 1
        try:
            shutil.move(str(path), str(dest))
        except OSError as exc:
            log.error("failed to quarantine %s: %s", path, exc)
            return
        reasons = "; ".join(f"[{f.code}] {f.message}" for f in result.findings)
        log.warning("QUARANTINED %s -> %s (%s)", path, dest, reasons)

    def run_forever(self) -> None:
        log.info("watching %s (poll every %.1fs), quarantine dir: %s",
                  ", ".join(str(d) for d in self.watch_dirs),
                  self.poll_interval, self.quarantine_dir)
        try:
            while True:
                self.scan_once()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            log.info("stopped")
