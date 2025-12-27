# tests/test_snort_parser.py

from pathlib import Path
import pytest

from src.snort_parser import parse_snort_file


def _resolve_sample_path() -> Path:
    """
    Prefer the "real" sample file if present, otherwise fall back to a fast.log
    location if you later add one. Uses paths relative to the repo root.
    """
    repo_root = Path(__file__).resolve().parent.parent

    candidates = [
        repo_root / "sample_data" / "snort_alert_real.log",
        repo_root / "sample_data" / "snort" / "fast.log",
    ]

    for p in candidates:
        if p.exists():
            return p

    # Nothing found
    return candidates[0]


def test_parse_real_snort_alert_file():
    path = _resolve_sample_path()
    if not path.exists():
        pytest.skip(f"Sample snort alert file not found. Expected one of: {path}")

    events = parse_snort_file(str(path))

    # We should have parsed at least one alert
    assert len(events) > 0

    event = events[0]

    # Core fields that MUST exist
    assert event["ts"] is not None
    assert event["gid"] is not None
    assert event["sid"] is not None
    assert event["rev"] is not None
    assert event["msg"] is not None
    assert event["proto"] is not None
    assert event["src_ip"] is not None
    assert event["dst_ip"] is not None

    # Optional fields (may be None, but must exist as keys)
    assert "classification" in event
    assert "priority" in event

