from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from typing import Optional, Iterable, Dict, Any

# --- IP patterns (IPv4 or IPv6) ---
IPV4_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV6_RE = r"[0-9A-Fa-f:]+"
IP_RE = rf"(?:{IPV4_RE}|{IPV6_RE})"

# Regex for Snort "fast" alert format
# Example:
# 08/24-12:34:56.789012  [**] [1:1000001:1] Message [**] [Priority: 2] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
# ICMP/no-port example:
# 09/12-14:22:11.123456  [**] [1:2100365:9] PING [**] [Priority: 3] {ICMP} 10.0.0.5 -> 8.8.8.8
FAST_LINE_RE = re.compile(
    rf"""
    ^
    (?P<ts>\d{{2}}/\d{{2}}-\d{{2}}:\d{{2}}:\d{{2}}\.\d+)\s+
    \[\*\*\]\s+
    \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+
    (?P<msg>.+?)\s+
    \[\*\*\]\s+
    \[Priority:\s+(?P<priority>\d+)\]\s+
    \{{(?P<proto>[A-Z0-9]+)\}}\s+
    (?P<src_ip>{IP_RE})(?::(?P<src_port>\d+))?\s+
    ->\s+
    (?P<dst_ip>{IP_RE})(?::(?P<dst_port>\d+))?
    $
    """,
    re.VERBOSE,
)


def priority_to_severity(priority: int) -> str:
    """
    Normalize Snort priority into SOC-style severity.
    """
    if priority == 1:
        return "high"
    if priority == 2:
        return "medium"
    if priority == 3:
        return "low"
    return "info"


@dataclass(frozen=True)
class SnortFastAlert:
    timestamp: str
    gid: int
    sid: int
    rev: int
    message: str
    priority: int
    severity: str
    protocol: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    tool: str = "snort"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert into a SIEM-friendly dictionary.
        """
        return asdict(self)

    def to_json(self) -> str:
        """
        JSON serialization for streaming or ingestion.
        """
        return json.dumps(self.to_dict(), sort_keys=True)


def parse_fast_line(line: str) -> Optional[SnortFastAlert]:
    """
    Parse a single Snort fast alert line.
    Returns SnortFastAlert if it matches expected format.
    """
    line = line.strip()
    if not line:
        return None

    match = FAST_LINE_RE.match(line)
    if not match:
        return None

    g = match.groupdict()
    priority = int(g["priority"])

    return SnortFastAlert(
        timestamp=g["ts"],
        gid=int(g["gid"]),
        sid=int(g["sid"]),
        rev=int(g["rev"]),
        message=g["msg"],
        priority=priority,
        severity=priority_to_severity(priority),
        protocol=g["proto"],
        src_ip=g["src_ip"],
        src_port=int(g["src_port"]) if g["src_port"] is not None else None,
        dst_ip=g["dst_ip"],
        dst_port=int(g["dst_port"]) if g["dst_port"] is not None else None,
    )


def parse_fast_file(path: str) -> Iterable[SnortFastAlert]:
    """
    Stream-parse a Snort fast alert file.
    Safe for large log files.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            alert = parse_fast_line(line)
            if alert:
                yield alert

