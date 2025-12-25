from src.parsers.snort_fast import parse_fast_line, priority_to_severity

SAMPLE_LINE = (
    "08/24-12:34:56.789012  [**] [1:1000001:1] Possible suspicious HTTP access "
    "[**] [Priority: 2] {TCP} 192.168.1.10:51515 -> 93.184.216.34:80"
)

BAD_LINE = "this is not a snort fast alert line"


def test_parse_fast_line_ipv6():
    ipv6_line = (
        "09/12-14:22:11.123456  [**] [1:3000001:1] IPv6 test alert "
        "[**] [Priority: 2] {TCP} "
        "2001:db8::1:443 -> 2001:db8::2:51515"
    )

    alert = parse_fast_line(ipv6_line)
    assert alert is not None
    assert alert.protocol == "TCP"
    assert alert.src_ip.startswith("2001:")
    assert alert.dst_ip.startswith("2001:")


def test_priority_to_severity_mapping():
    assert priority_to_severity(1) == "high"
    assert priority_to_severity(2) == "medium"
    assert priority_to_severity(3) == "low"
    assert priority_to_severity(4) == "info"
    assert priority_to_severity(999) == "info"


def test_parse_fast_line_success():
    alert = parse_fast_line(SAMPLE_LINE)
    assert alert is not None

    assert alert.timestamp == "08/24-12:34:56.789012"
    assert alert.gid == 1
    assert alert.sid == 1000001
    assert alert.rev == 1
    assert alert.message == "Possible suspicious HTTP access"
    assert alert.priority == 2
    assert alert.severity == "medium"
    assert alert.protocol == "TCP"
    assert alert.src_ip == "192.168.1.10"
    assert alert.src_port == 51515
    assert alert.dst_ip == "93.184.216.34"
    assert alert.dst_port == 80
    assert alert.tool == "snort"


def test_parse_fast_line_blank_returns_none():
    assert parse_fast_line("") is None
    assert parse_fast_line("   ") is None


def test_parse_fast_line_bad_returns_none():
    assert parse_fast_line(BAD_LINE) is None
