# src/detect.py

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Optional

from src.snort_fast import AlertEvent


@dataclass(frozen=True)
class BurstFinding:
    src_ip: str
    count: int
    window_seconds: int
    start_ts: str
    end_ts: str


def detect_src_ip_bursts(
    events: Iterable[AlertEvent],
    *,
    threshold: int = 5,
    window_seconds: int = 300,
) -> list[BurstFinding]:
    """
    Detect bursts where the SAME src_ip triggers >= threshold alerts within window_seconds.

    Assumptions:
    - events have ts_dt filled in (from parse_fast_line(... year=..., tz=...))
    - events are roughly time-ordered (if not, we sort defensively)
    """
    ev_list = list(events)
    if not ev_list:
        return []

    # Defensive sort by time (safe for lab-scale data)
    ev_list.sort(key=lambda e: e.ts_dt)

    # For each src_ip, maintain a sliding time window of events (deque)
    windows: dict[str, deque[AlertEvent]] = {}

    findings: list[BurstFinding] = []
    window = timedelta(seconds=window_seconds)

    for e in ev_list:
        dq = windows.setdefault(e.src_ip, deque())
        dq.append(e)

        # Slide: remove events older than (current_time - window)
        cutoff = e.ts_dt - window
        while dq and dq[0].ts_dt < cutoff:
            dq.popleft()

        # If we hit threshold, record a finding using the current window
        if len(dq) >= threshold:
            findings.append(
                BurstFinding(
                    src_ip=e.src_ip,
                    count=len(dq),
                    window_seconds=window_seconds,
                    start_ts=dq[0].ts,
                    end_ts=dq[-1].ts,
                )
            )
            # Optional: prevent spamming repeated findings for the same burst
            # Clear the deque so we only alert once per burst.
            dq.clear()

    return findings
