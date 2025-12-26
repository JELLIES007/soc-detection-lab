from __future__ import annotations

import re
from typing import Dict, Iterator, List, Optional


# Matches BOTH of these styles (your real examples):
# 12/25-16:11:37.070241  [**] [1:1000001:1] MSG [**] [Priority: 0] {ICMP} 127.0.0.1 -> 127.0.0.1
# 12/25-16:11:37.070241  [**] [1:527:8] MSG [**] [Classification: ...] [Priority: 2] {ICMP} 127.0.0.1 -> 127.0.0.1
#
# Also tolerates extra spaces and optional src/dst ports.
FASTISH_RE = re.compile(
    r"^\s*"
    r"(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>.*?)\]\s+)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s+)?"
    r"\{(?P<proto>[A-Za-z0-9_]+)\}\s+"
    r"(?P<src_ip>[^:\s]+)(?::(?P<src_port>\d+))?\s+->\s+"
    r"(?P<dst_ip>[^:\s]+)(?::(?P<dst_port>\d+))?\s*"
    r"$"
)


def normalize_event(
    *,
    raw: str,
    fmt: str,
    ts: Optional[str] = None,
    gid: Optional[str] = None,
    sid: Optional[str] = None,
    rev: Optional[str] = None,
    msg: Optional[str] = None,
    classification: Optional[str] = None,
    priority: Optional[str] = None,
    proto: Optional[str] = None,
    src_ip: Optional[str] = None,
    src_port: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """Single schema used everywhere (tests, JSONL output, SIEM pipelines)."""
    return {
        "ts": ts,
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "msg": msg,
        "classification": classification,
        "priority": priority,
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": raw,
        "format": fmt,  # e.g. "fast"
    }


def parse_snort_line(line: str) -> Optional[Dict[str, Optional[str]]]:
    """
    Parses a single Snort one-line alert (fast-ish format).
    Returns a normalized event dict, or None if the line doesn't match.
    """
    s = line.rstrip("\n")
    m = FASTISH_RE.match(s)
    if not m:
        return None

    d = m.groupdict()
    return normalize_event(
        raw=s,
        fmt="fast",
        ts=d.get("ts"),
        gid=d.get("gid"),
        sid=d.get("sid"),
        rev=d.get("rev"),
        msg=d.get("msg"),
        classification=(d.get("classification") or None),
        priority=(d.get("priority") or None),
        proto=(d.get("proto") or None),
        src_ip=(d.get("src_ip") or None),
        src_port=(d.get("src_port") or None),
        dst_ip=(d.get("dst_ip") or None),
        dst_port=(d.get("dst_port") or None),
    )


def iter_snort_events(lines: Iterator[str]) -> Iterator[Dict[str, Optional[str]]]:
    """Stream parser: yields events from any iterable of lines."""
    for line in lines:
        evt = parse_snort_line(line)
        if evt:
            yield evt


def parse_snort_text(text: str) -> List[Dict[str, Optional[str]]]:
    """Convenience: parse full file content into a list of normalized events."""
    return list(iter_snort_events(iter(text.splitlines(True))))


def parse_snort_file(path: str) -> List[Dict[str, Optional[str]]]:
    """Convenience: read a file and parse it."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return list(iter_snort_events(f))

