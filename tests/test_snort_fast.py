# tests/test_snort_fast.py

import io
from src.snort_fast import (
    parse_fast_line,
    iter_fast_events,
    AlertEvent,
)


VALID_FAST_LINE = (
    '12/25-14:32:10.123456 [**] [1:1000001:1] '
    'SOC LAB TEST: ICMP Ping Detected [**] '
    '[Classification: Misc activity] [Priority: 3] '
    '{ICMP} 192.168.1.10 -> 8.8.8.8'
)


def test_parse_fast_line_valid():
    event = parse_fast_line(VALID_FAST_LINE)

    assert isinstance(event, AlertEvent)
    assert event.ts == "12/25-14:32:10.123456"
    assert event.message == "SOC LAB TEST: ICMP Ping Detected"
    assert event.classification == "Misc activity"
    assert event.priority == 3
    assert event.proto == "ICMP"

    assert event.src_ip == "192.168.1.10"
    assert event.src_port is None
    assert event.dst_ip == "8.8.8.8"
    assert event.dst_port is None

    assert event.gid == 1
    assert event.sid == 1000001
    assert event.rev == 1


def test_parse_fast_line_invalid_returns_none():
    bad_line = "this is not a snort log line"
    event = parse_fast_line(bad_line)

    assert event is None


def test_iter_fast_events_multiple_lines():
    log_data = "\n".join([
        VALID_FAST_LINE,
        "invalid garbage line",
        VALID_FAST_LINE,
    ])

    fake_file = io.StringIO(log_data)
    events = list(iter_fast_events(fake_file))

    assert len(events) == 2
    assert all(isinstance(e, AlertEvent) for e in events)

