"""Best-effort repair of a flagged .tgs file: clamp hostile numeric values
and cut circular precomposition references, instead of just deleting the
file outright. Useful when you want to keep looking at a sticker pack
without trusting every number in it.

This is a defense-in-depth convenience, not a guarantee -- when in doubt,
prefer quarantining the original (see antistiker.watcher) over shipping a
"repaired" file to anyone else.
"""

from __future__ import annotations

import copy
import gzip
import io
import json
import math
from typing import Any

from .tgs_scan import (
    MAX_NUMBER_MAGNITUDE,
    MAX_POLYSTAR_POINTS,
    MAX_RADIUS_MAGNITUDE,
    TgsDecodeError,
    decompress_tgs,
    parse_lottie,
)


def _clamp(value: float, bound: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(-bound, min(bound, value))


def _clamp_property(prop: Any, bound: float) -> None:
    """Mutate a Lottie property's numeric leaves in place, clamping them."""
    if isinstance(prop, bool):
        return
    if isinstance(prop, (int, float)):
        return  # caller replaces scalars; lists/dicts are mutated below
    if isinstance(prop, list):
        for i, item in enumerate(prop):
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                prop[i] = _clamp(item, bound)
            else:
                _clamp_property(item, bound)
    elif isinstance(prop, dict):
        for key in ("s", "e", "k"):
            if key in prop:
                if isinstance(prop[key], (int, float)) and not isinstance(prop[key], bool):
                    prop[key] = _clamp(prop[key], bound)
                else:
                    _clamp_property(prop[key], bound)


def _sanitize_node(node: Any, broken_refs: set[str]) -> None:
    if isinstance(node, dict):
        if node.get("ty") == "sr":
            for key, bound in (("pt", MAX_POLYSTAR_POINTS), ("ir", MAX_RADIUS_MAGNITUDE),
                                ("or", MAX_RADIUS_MAGNITUDE)):
                if key in node:
                    _clamp_property(node[key], bound)
        if node.get("ty") == 0 and node.get("refId") in broken_refs:
            node["refId"] = None
        for value in node.values():
            if isinstance(value, (dict, list)):
                _sanitize_node(value, broken_refs)
        # generic clamp pass for any other absurd numeric leaves
        for key, value in list(node.items()):
            if isinstance(value, dict) and ("k" in value or "s" in value):
                _clamp_property(value, MAX_NUMBER_MAGNITUDE)
    elif isinstance(node, list):
        for item in node:
            _sanitize_node(item, broken_refs)


def _cyclic_asset_ids(doc: dict) -> set[str]:
    from .tgs_scan import _asset_graph  # reuse graph-building logic

    graph = _asset_graph(doc)
    broken: set[str] = set()
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}

    def dfs(node: str, stack: list[str]) -> None:
        color[node] = GRAY
        stack.append(node)
        for neighbor in graph.get(node, ()):
            if neighbor not in graph:
                continue
            if color[neighbor] == GRAY:
                broken.add(neighbor)
            elif color[neighbor] == WHITE:
                dfs(neighbor, stack)
        stack.pop()
        color[node] = BLACK

    for node in list(graph):
        if color[node] == WHITE:
            dfs(node, [])
    return broken


def sanitize_bytes(raw: bytes) -> bytes:
    """Return a re-gzipped, clamped/repaired copy of a .tgs payload.

    Raises TgsDecodeError if the file can't even be safely parsed -- there's
    nothing to repair in that case, only to discard.
    """
    payload = decompress_tgs(raw)
    doc = parse_lottie(payload)
    if not isinstance(doc, dict):
        raise TgsDecodeError("top-level JSON value is not an object")

    doc = copy.deepcopy(doc)
    for key in ("w", "h", "fr", "ip", "op"):
        if key in doc and isinstance(doc[key], (int, float)) and not isinstance(doc[key], bool):
            doc[key] = _clamp(doc[key], MAX_NUMBER_MAGNITUDE)

    broken_refs = _cyclic_asset_ids(doc)
    _sanitize_node(doc.get("layers"), broken_refs)
    for asset in doc.get("assets") or []:
        if isinstance(asset, dict) and "layers" in asset:
            _sanitize_node(asset["layers"], broken_refs)

    cleaned_json = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(cleaned_json)
    return buf.getvalue()


def sanitize_file(src: str, dst: str) -> None:
    from pathlib import Path

    raw = Path(src).read_bytes()
    cleaned = sanitize_bytes(raw)
    Path(dst).write_bytes(cleaned)
