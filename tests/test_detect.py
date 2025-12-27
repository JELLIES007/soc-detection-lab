# tests/test_detect.py

from datetime import datetime, timedelta

from src.detect import detect_src_ip_bursts


def _evt(src_ip: str, dt: datetime, ts: str = "12/25-00:00:00.000000"):
    # minimal shape matching AlertEvent fields we use: src_ip, ts_dt, ts
    class E:
        def __init__(self, src_ip, ts_dt, ts):
            self.src_ip = src_ip
            self.ts_dt = ts_dt
            self.ts = ts

    return E(src_ip, dt, ts)


def test_detect_src_ip_bursts_finds_burst():
    base = datetime(2025, 12, 25, 10, 0, 0)

    events = [
        _evt("1.1.1.1", base + timedelta(seconds=0), "12/25-10:00:00.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=30), "12/25-10:00:30.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=60), "12/25-10:01:00.000000"),
        _evt("2.2.2.2", base + timedelta(seconds=70), "12/25-10:01:10.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=90), "12/25-10:01:30.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=120), "12/25-10:02:00.000000"),
    ]

    findings = detect_src_ip_bursts(events, threshold=5, window_seconds=300)
    assert len(findings) == 1
    f = findings[0]
    assert f.src_ip == "1.1.1.1"
    assert f.count == 5
    assert f.start_ts == "12/25-10:00:00.000000"
    assert f.end_ts == "12/25-10:02:00.000000"


def test_detect_src_ip_bursts_no_burst_if_outside_window():
    base = datetime(2025, 12, 25, 10, 0, 0)

    events = [
        _evt("1.1.1.1", base + timedelta(seconds=0), "12/25-10:00:00.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=400), "12/25-10:06:40.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=800), "12/25-10:13:20.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=1200), "12/25-10:20:00.000000"),
        _evt("1.1.1.1", base + timedelta(seconds=1600), "12/25-10:26:40.000000"),
    ]

    findings = detect_src_ip_bursts(events, threshold=3, window_seconds=300)
    assert findings == []
