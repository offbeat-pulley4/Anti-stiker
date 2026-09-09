"""Best-guess locations to watch for stray .tgs files on each platform.

Important limitation: AyuGram/Telegram Desktop do NOT store stickers
received in chats as plain .tgs files on disk -- they live inside the
client's internal cache database (Storage::Cache blobs under its tdata
directory), which this tool does not parse or touch. What this *does*
protect against is the locally-triggered crash: a malicious .tgs sitting
in your Downloads folder (or wherever you save/receive sticker files
outside the app) that you're about to drag-and-drop, forward, or import
into AyuGram. That is also the exact scenario the well-known "kill
sticker" local crash relies on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def default_watch_dirs() -> list[Path]:
    dirs: list[Path] = []
    home = Path.home()

    downloads = home / "Downloads"
    if downloads.exists():
        dirs.append(downloads)

    if sys.platform.startswith("linux"):
        xdg_download = os.environ.get("XDG_DOWNLOAD_DIR")
        if xdg_download and Path(xdg_download).exists():
            dirs.append(Path(xdg_download))
    elif sys.platform == "darwin":
        pass  # Downloads already covered above
    elif sys.platform == "win32":
        pass  # Downloads already covered above

    # De-duplicate while preserving order.
    seen: set[Path] = set()
    unique: list[Path] = []
    for d in dirs:
        resolved = d.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(d)
    return unique
