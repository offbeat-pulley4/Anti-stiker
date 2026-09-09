"""Core scanning logic for .tgs (gzipped Lottie JSON) sticker files.

A .tgs "kill sticker" crashes Telegram-family clients (AyuGram, Telegram
Desktop, ...) by putting an absurd or structurally hostile value somewhere
the renderer (rlottie) trusts blindly -- e.g. a polystar "points" count of
1e38, a circular precomposition reference, or a multi-gigabyte decompressed
payload hidden behind a tiny gzip stream. None of that requires a chat
connection: dropping such a file onto the client, or opening a downloaded
sticker pack, is enough to trigger it.

This module parses a .tgs file the same way a renderer would, but stays
paranoid at every step: bounded decompression, a bounded/iterative walk of
the document tree, and explicit sanity limits on every field known to have
caused real-world crashes. Nothing here executes or renders the animation.
"""

from __future__ import annotations

import gzip
import io
import json
import math
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Iterator

# ---------------------------------------------------------------------------
# Thresholds. These are deliberately generous relative to what a legitimate
# sticker ever needs (Telegram itself caps .tgs at 64 KB, 512x512, <=3s) so
# real sticker packs never trip them, while the known crash patterns blow
# straight through.
# ---------------------------------------------------------------------------
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024  # real stickers are well under 64 KB
MAX_VISITED_NODES = 200_000  # guards the scanner itself against JSON bombs
MAX_LAYERS = 500
MAX_ASSETS = 500
MAX_KEYFRAMES_PER_PROPERTY = 4_000
MAX_PRECOMP_DEPTH = 24
MAX_NUMBER_MAGNITUDE = 1e6  # generic ceiling for any numeric leaf in the doc
MAX_POLYSTAR_POINTS = 1_000  # rlottie/Telegram never need more spikes than this
MAX_RADIUS_MAGNITUDE = 1e5


class Verdict(IntEnum):
    SAFE = 0
    SUSPICIOUS = 1
    MALICIOUS = 2

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name


@dataclass(frozen=True)
class Finding:
    verdict: Verdict
    code: str
    message: str
    path: str = ""


@dataclass
class ScanResult:
    file: str
    verdict: Verdict = Verdict.SAFE
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return self.verdict == Verdict.SAFE

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.verdict > self.verdict:
            self.verdict = finding.verdict


class TgsDecodeError(Exception):
    """Raised when a file can't even be safely decompressed/parsed."""


# ---------------------------------------------------------------------------
# Decompression / parsing
# ---------------------------------------------------------------------------

def decompress_tgs(raw: bytes, max_bytes: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Gzip-decompress with a hard cap so a gzip bomb can't exhaust memory
    while we're merely *scanning* the file."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = gz.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise TgsDecodeError(
                        f"decompressed payload exceeds {max_bytes} bytes "
                        "(gzip-bomb pattern)"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except OSError as exc:
        raise TgsDecodeError(f"not a valid gzip stream: {exc}") from exc


def _reject_constant(token: str) -> float:
    raise TgsDecodeError(f"non-finite numeric literal '{token}' in JSON")


def parse_lottie(payload: bytes) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TgsDecodeError(f"payload is not valid UTF-8 JSON: {exc}") from exc
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise TgsDecodeError(f"malformed JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------

def _iter_numbers(value: Any) -> Iterator[float]:
    """Yield every numeric leaf reachable from a Lottie property value,
    whether it's a bare number, a static [x, y] array, or a list of
    keyframe objects (animated property)."""
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        yield float(value)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_numbers(item)
    elif isinstance(value, dict):
        for key in ("s", "e", "k"):
            if key in value:
                yield from _iter_numbers(value[key])


def _prop_numbers(node: dict, key: str) -> Iterator[float]:
    prop = node.get(key)
    if prop is None:
        return
    yield from _iter_numbers(prop.get("k") if isinstance(prop, dict) else prop)


def _keyframe_count(node: dict, key: str) -> int:
    prop = node.get(key)
    if not isinstance(prop, dict):
        return 0
    k = prop.get("k")
    return len(k) if isinstance(k, list) and prop.get("a") == 1 else 0


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

def _check_polystar(node: dict, path: str, result: ScanResult) -> None:
    for key, bound, label in (
        ("pt", MAX_POLYSTAR_POINTS, "point count"),
        ("ir", MAX_RADIUS_MAGNITUDE, "inner radius"),
        ("or", MAX_RADIUS_MAGNITUDE, "outer radius"),
    ):
        for num in _prop_numbers(node, key):
            if not math.isfinite(num):
                result.add(Finding(
                    Verdict.MALICIOUS, "polystar-nonfinite",
                    f"polystar '{label}' is non-finite ({num})", path,
                ))
            elif abs(num) > bound:
                result.add(Finding(
                    Verdict.MALICIOUS, "polystar-bound",
                    f"polystar '{label}' = {num!r} exceeds safe bound {bound} "
                    "(matches known kill-sticker resource-exhaustion pattern)",
                    path,
                ))


def _check_generic_numbers(node: dict, path: str, result: ScanResult) -> None:
    for key, value in node.items():
        if key in ("ip", "op", "st", "fr", "w", "h", "id"):
            continue  # timing/dimension fields checked separately at the root
        if isinstance(value, dict) and ("k" in value or "s" in value or "e" in value):
            for num in _iter_numbers(value):
                if not math.isfinite(num):
                    result.add(Finding(
                        Verdict.MALICIOUS, "nonfinite-value",
                        f"field '{key}' contains a non-finite value", path,
                    ))
                elif abs(num) > MAX_NUMBER_MAGNITUDE:
                    result.add(Finding(
                        Verdict.MALICIOUS, "numeric-bound",
                        f"field '{key}' = {num!r} is absurdly large "
                        "(kill-sticker pattern: oversized numeric field)",
                        path,
                    ))


def _walk_document(doc: dict, result: ScanResult) -> None:
    """Iteratively walk every node once, applying bounded-cost checks.
    Iterative on purpose: a maliciously deep JSON tree must not be able to
    blow the *scanner's* Python call stack."""
    stack: list[tuple[Any, str]] = [(doc, "$")]
    visited = 0
    while stack:
        node, path = stack.pop()
        visited += 1
        if visited > MAX_VISITED_NODES:
            result.add(Finding(
                Verdict.MALICIOUS, "too-complex",
                f"document exceeds {MAX_VISITED_NODES} nodes; refusing to "
                "keep analyzing (possible resource-exhaustion bomb)",
                path,
            ))
            return

        if isinstance(node, dict):
            if node.get("ty") == "sr":
                _check_polystar(node, path, result)
            _check_generic_numbers(node, path, result)

            shapes = node.get("shapes")
            if isinstance(shapes, list) and len(shapes) > MAX_LAYERS:
                result.add(Finding(
                    Verdict.MALICIOUS, "shape-bomb",
                    f"{len(shapes)} shapes in one group exceeds safe limit", path,
                ))

            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    stack.append((value, f"{path}.{key}"))

            for key in list(node.keys()):
                cnt = _keyframe_count(node, key)
                if cnt > MAX_KEYFRAMES_PER_PROPERTY:
                    result.add(Finding(
                        Verdict.MALICIOUS, "keyframe-bomb",
                        f"property '{key}' has {cnt} keyframes, exceeds "
                        f"safe limit {MAX_KEYFRAMES_PER_PROPERTY}", path,
                    ))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                if isinstance(item, (dict, list)):
                    stack.append((item, f"{path}[{i}]"))


def _asset_graph(doc: dict) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}

    def refs_in_layers(layers: Any) -> set[str]:
        out: set[str] = set()
        if isinstance(layers, list):
            for layer in layers:
                if isinstance(layer, dict) and layer.get("ty") == 0:
                    ref = layer.get("refId")
                    if isinstance(ref, str):
                        out.add(ref)
        return out

    for asset in doc.get("assets") or []:
        if isinstance(asset, dict) and isinstance(asset.get("id"), str):
            graph[asset["id"]] = refs_in_layers(asset.get("layers"))
    graph["$root"] = refs_in_layers(doc.get("layers"))
    return graph


def _check_precomp_graph(doc: dict, result: ScanResult) -> None:
    graph = _asset_graph(doc)

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in graph}
    depth: dict[str, int] = {}

    def dfs(node: str, current_depth: int) -> bool:
        color[node] = GRAY
        depth[node] = current_depth
        if current_depth > MAX_PRECOMP_DEPTH:
            result.add(Finding(
                Verdict.MALICIOUS, "precomp-depth",
                f"precomposition nesting exceeds {MAX_PRECOMP_DEPTH} levels "
                "(stack-overflow / recursion-bomb pattern)", f"assets.{node}",
            ))
            color[node] = BLACK
            return True
        for neighbor in graph.get(node, ()):  # neighbor may be unknown asset id
            if neighbor not in graph:
                continue
            if color[neighbor] == GRAY:
                result.add(Finding(
                    Verdict.MALICIOUS, "precomp-cycle",
                    f"circular precomposition reference '{node}' -> "
                    f"'{neighbor}' (infinite-recursion kill-sticker pattern)",
                    f"assets.{node}",
                ))
                return True
            if color[neighbor] == WHITE:
                if dfs(neighbor, current_depth + 1):
                    return True
        color[node] = BLACK
        return False

    for node in list(graph):
        if color[node] == WHITE:
            dfs(node, 0)


def _check_root_fields(doc: dict, result: ScanResult) -> None:
    required = {"v", "fr", "ip", "op", "w", "h", "layers"}
    missing = required - doc.keys()
    if missing:
        result.add(Finding(
            Verdict.MALICIOUS, "missing-fields",
            f"missing required top-level field(s): {sorted(missing)}",
        ))
        return

    for key in ("w", "h", "fr", "ip", "op"):
        val = doc.get(key)
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            result.add(Finding(Verdict.MALICIOUS, "bad-type",
                                f"top-level '{key}' is not numeric"))
        elif not math.isfinite(val) or abs(val) > MAX_NUMBER_MAGNITUDE:
            result.add(Finding(Verdict.MALICIOUS, "numeric-bound",
                                f"top-level '{key}' = {val!r} is out of range"))

    layers = doc.get("layers")
    if isinstance(layers, list) and len(layers) > MAX_LAYERS:
        result.add(Finding(Verdict.MALICIOUS, "layer-bomb",
                            f"{len(layers)} top-level layers exceeds safe limit"))
    assets = doc.get("assets")
    if isinstance(assets, list) and len(assets) > MAX_ASSETS:
        result.add(Finding(Verdict.MALICIOUS, "asset-bomb",
                            f"{len(assets)} assets exceeds safe limit"))

    w, h = doc.get("w"), doc.get("h")
    if isinstance(w, (int, float)) and isinstance(h, (int, float)):
        if w != 512 or h != 512:
            result.add(Finding(Verdict.SUSPICIOUS, "nonstandard-size",
                                f"canvas is {w}x{h}, Telegram stickers are 512x512"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_bytes(raw: bytes, name: str = "<memory>") -> ScanResult:
    result = ScanResult(file=name)
    try:
        payload = decompress_tgs(raw)
        doc = parse_lottie(payload)
    except TgsDecodeError as exc:
        result.add(Finding(Verdict.MALICIOUS, "decode-error", str(exc)))
        return result

    if not isinstance(doc, dict):
        result.add(Finding(Verdict.MALICIOUS, "bad-root",
                            "top-level JSON value is not an object"))
        return result

    _check_root_fields(doc, result)
    _walk_document(doc, result)
    _check_precomp_graph(doc, result)
    return result


def scan_file(path: str | Path) -> ScanResult:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        result = ScanResult(file=str(path))
        result.add(Finding(Verdict.MALICIOUS, "read-error", str(exc)))
        return result
    return scan_bytes(raw, name=str(path))


def iter_tgs_files(root: str | Path) -> Iterable[Path]:
    root = Path(root)
    if root.is_file():
        yield root
        return
    yield from root.rglob("*.tgs")
