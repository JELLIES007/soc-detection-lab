from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO, Union
import json
import re
from datetime import datetime, tzinfo


@dataclass(frozen=True)
class AlertEvent:
    ts: str                 # "MM/DD-HH:MM:SS.micro"
    ts_dt: datetime         # injected year datetime
    message: str
    classification: Optional[str]
    priority: Optional[int]
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    proto: Optional[str]
    gid: Optional[int]
    sid: Optional[int]
    rev: Optional[int]
    raw: str


FAST_LINE_RE = re.compile(
    r"""
    ^
    (?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+
    \[\*\*\]\s+\[(?P<siginfo>[^\]]+)\]\s+(?P<msg>.+?)\s+\[\*\*\]\s+
    (?:\[Classification:\s+(?P<class>.+?)\]\s+)?   # optional
    (?:\[Priority:\s+(?P<prio>\d+)\]\s+)?         # optional
    \{(?P<proto>[^}]+)\}\s+
    (?P<src>[^ ]+)\s+->\s+(?P<dst>[^ ]+)
    \s*$
    """,
    re.VERBOSE,
)

IP_PORT_RE = re.compile(r"^(?P<ip>[^:]+)(?::(?P<port>\d+))?$")
SIGINFO_RE = re.compile(r"^(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)$")


def parse_fast_ts(ts: str, *, year: Optional[int] = None, tz: Optional[tzinfo] = None) -> datetime:
    if year is None:
        year = datetime.now().year

    base = datetime.strptime(ts, "%m/%d-%H:%M:%S.%f")
    dt = base.replace(year=year)

    if tz is not None:
        dt = dt.replace(tzinfo=tz)

    return dt


def parse_fast_line(line: str, *, year: Optional[int] = None, tz: Optional[tzinfo] = None) -> Optional[AlertEvent]:
    raw = line.rstrip("\n")
    if not raw.strip():
        return None

    m = FAST_LINE_RE.match(raw)
    if not m:
        return None

    ts = m.group("ts")
    ts_dt = parse_fast_ts(ts, year=year, tz=tz)

    msg = m.group("msg").strip()
    classification = m.group("class").strip() if m.group("class") else None
    priority = int(m.group("prio")) if m.group("prio") else None
    proto = m.group("proto").strip() if m.group("proto") else None

    src_ip, src_port = _split_ip_port(m.group("src").strip())
    dst_ip, dst_port = _split_ip_port(m.group("dst").strip())

    gid, sid, rev = _parse_siginfo(m.group("siginfo").strip())

    return AlertEvent(
        ts=ts,
        ts_dt=ts_dt,
        message=msg,
        classification=classification,
        priority=priority,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        gid=gid,
        sid=sid,
        rev=rev,
        raw=raw,
    )


def iter_fast_events(fp: TextIO, *, year: Optional[int] = None, tz: Optional[tzinfo] = None) -> Iterator[AlertEvent]:
    for line in fp:
        evt = parse_fast_line(line, year=year, tz=tz)
        if evt is not None:
            yield evt


def read_fast_log(
    path: Union[str, Path],
    *,
    year: Optional[int] = None,
    tz: Optional[tzinfo] = None,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> list[AlertEvent]:
    p = Path(path)
    with p.open("r", encoding=encoding, errors=errors) as f:
        return list(iter_fast_events(f, year=year, tz=tz))


def write_jsonl(events: Iterable[AlertEvent], out_path: Union[str, Path]) -> Path:
    p = Path(out_path)
    with p.open("w", encoding="utf-8") as f:
        for evt in events:
            d = asdict(evt)
            d["ts_dt"] = evt.ts_dt.isoformat()
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    return p


def _split_ip_port(token: str) -> tuple[str, Optional[int]]:
    m = IP_PORT_RE.match(token)
    if not m:
        return token, None
    ip = m.group("ip")
    port = int(m.group("port")) if m.group("port") else None
    return ip, port


def _parse_siginfo(siginfo: str) -> tuple[Optional[int], Optional[int], Optional[int]]:
    m = SIGINFO_RE.match(siginfo)
    if not m:
        return None, None, None
    return int(m.group("gid")), int(m.group("sid")), int(m.group("rev"))

