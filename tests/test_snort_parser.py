from src.snort_parser import parse_snort_file


def test_parse_real_snort_alert_file():
    events = parse_snort_file("sample_data/snort_alert_real.log")

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
