import gzip
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antistiker.sanitize import sanitize_bytes
from antistiker.tgs_scan import TgsDecodeError, Verdict, scan_bytes, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def _gzip_json(doc) -> bytes:
    raw = json.dumps(doc).encode()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw)
    return buf.getvalue()


def test_real_kill_sticker_is_malicious():
    result = scan_file(FIXTURES / "kill_sticker.tgs")
    assert result.verdict == Verdict.MALICIOUS
    codes = {f.code for f in result.findings}
    assert "polystar-bound" in codes or "numeric-bound" in codes


def test_safe_sticker_is_safe():
    result = scan_file(FIXTURES / "safe_sticker.tgs")
    assert result.verdict == Verdict.SAFE, result.findings


def test_gzip_bomb_is_rejected():
    huge = b"0" * (20 * 1024 * 1024)
    doc = {"v": "5.7.4", "fr": 30, "ip": 0, "op": 30, "w": 512, "h": 512,
           "assets": [], "layers": [], "padding": huge.decode()}
    result = scan_bytes(_gzip_json(doc))
    assert result.verdict == Verdict.MALICIOUS
    assert any(f.code == "decode-error" for f in result.findings)


def test_non_finite_literal_is_rejected():
    raw = b'{"v":"5.7.4","fr":30,"ip":0,"op":30,"w":512,"h":512,"assets":[],' \
          b'"layers":[{"ty":4,"ks":{"o":{"a":0,"k":NaN}},"shapes":[]}]}'
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(raw)
    result = scan_bytes(buf.getvalue())
    assert result.verdict == Verdict.MALICIOUS


def test_circular_precomp_reference_is_rejected():
    doc = {
        "v": "5.7.4", "fr": 30, "ip": 0, "op": 30, "w": 512, "h": 512,
        "assets": [
            {"id": "comp_0", "layers": [{"ty": 0, "refId": "comp_1"}]},
            {"id": "comp_1", "layers": [{"ty": 0, "refId": "comp_0"}]},
        ],
        "layers": [{"ty": 0, "refId": "comp_0"}],
    }
    result = scan_bytes(_gzip_json(doc))
    assert result.verdict == Verdict.MALICIOUS
    assert any(f.code == "precomp-cycle" for f in result.findings)


def test_not_gzip_at_all():
    result = scan_bytes(b"not a gzip stream")
    assert result.verdict == Verdict.MALICIOUS
    assert result.findings[0].code == "decode-error"


def test_nonstandard_canvas_size_is_only_suspicious():
    doc = {"v": "5.7.4", "fr": 30, "ip": 0, "op": 30, "w": 100, "h": 100,
           "assets": [], "layers": []}
    result = scan_bytes(_gzip_json(doc))
    assert result.verdict == Verdict.SUSPICIOUS


def test_sanitize_defuses_kill_sticker():
    raw = (FIXTURES / "kill_sticker.tgs").read_bytes()
    cleaned = sanitize_bytes(raw)
    result = scan_bytes(cleaned)
    assert result.verdict == Verdict.SAFE, result.findings


def test_sanitize_raises_on_unparseable_input():
    try:
        sanitize_bytes(b"garbage")
    except TgsDecodeError:
        pass
    else:
        raise AssertionError("expected TgsDecodeError")
