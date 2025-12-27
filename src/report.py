# src/report.py

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from src.snort_fast import read_fast_log, AlertEvent
from src.detect import detect_src_ip_bursts


def severity_from_priority(priority: Optional[int]) -> str:
    """
    Common SOC-ish mapping:
      1 -> HIGH
      2 -> MEDIUM
      3 -> LOW
      None/other -> UNKNOWN
    """
    if priority == 1:
        return "HIGH"
    if priority == 2:
        return "MEDIUM"
    if priority == 3:
        return "LOW"
    return "UNKNOWN"


def _effective_burst_threshold(requested: int, total_events: int) -> int:
    """
    Make burst detection demonstrable on small samples.

    Rules:
    - Never go below 2 (otherwise 1 event becomes a "burst")
    - If total events < requested threshold, scale down to total_events (but at least 2)
    """
    if total_events <= 0:
        return requested
    if total_events < requested:
        return max(2, total_events)
    return requested


def generate_soc_report(
    fast_log_path: str | Path,
    *,
    year: int,
    top_n: int = 10,
    burst_threshold: int = 3,          # <- lower default to demo on small samples
    burst_window_seconds: int = 300,
) -> str:
    events = read_fast_log(fast_log_path, year=year)

    lines: list[str] = []
    lines.append("SOC Detection Lab Report")
    lines.append(f"Input: {fast_log_path}")
    lines.append(f"Events parsed: {len(events)}")

    if not events:
        return "\n".join(lines)

    # Severity overview
    sev_counts = Counter(severity_from_priority(e.priority) for e in events)
    lines.append("")
    lines.append("Severity breakdown (from Priority):")
    for sev in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        if sev in sev_counts:
            lines.append(f"  {sev}: {sev_counts[sev]}")

    # Top talkers
    by_src = Counter(e.src_ip for e in events)
    lines.append("")
    lines.append(f"Top {top_n} source IPs by alert count:")
    for ip, n in by_src.most_common(top_n):
        lines.append(f"  {ip}: {n}")

    # Top signatures + show most-severe priority seen for each signature
    sig_counts: Counter[tuple[Optional[int], Optional[int], Optional[int], str]] = Counter()
    sig_best_priority: dict[tuple[Optional[int], Optional[int], Optional[int], str], Optional[int]] = {}

    for e in events:
        key = (e.gid, e.sid, e.rev, e.message)
        sig_counts[key] += 1

        # "Most severe" = lowest priority number (1 is more severe than 3)
        cur = sig_best_priority.get(key)
        if e.priority is None:
            # don't overwrite a known numeric priority
            sig_best_priority.setdefault(key, cur)
        else:
            if cur is None or e.priority < cur:
                sig_best_priority[key] = e.priority

    lines.append("")
    lines.append(f"Top {top_n} signatures by frequency:")
    for (gid, sid, rev, msg), n in sig_counts.most_common(top_n):
        p = sig_best_priority.get((gid, sid, rev, msg))
        sev = severity_from_priority(p)
        prio_str = str(p) if p is not None else "None"
        lines.append(f"  [{gid}:{sid}:{rev}] {n}  sev={sev} prio={prio_str}  {msg}")

    # Burst findings (auto-scale threshold for small samples)
    eff_threshold = _effective_burst_threshold(burst_threshold, len(events))
    findings = detect_src_ip_bursts(
        events,
        threshold=eff_threshold,
        window_seconds=burst_window_seconds,
    )

    lines.append("")
    if eff_threshold != burst_threshold:
        lines.append(
            f"Burst findings (auto-scaled threshold: requested={burst_threshold}, effective={eff_threshold}) "
            f"in {burst_window_seconds}s: {len(findings)}"
        )
    else:
        lines.append(
            f"Burst findings (>= {burst_threshold} alerts in {burst_window_seconds}s): {len(findings)}"
        )

    for f in findings[:top_n]:
        lines.append(
            f"  src={f.src_ip} count={f.count} window={f.window_seconds}s start={f.start_ts} end={f.end_ts}"
        )

    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    from datetime import datetime

    ap = argparse.ArgumentParser(description="Generate a SOC-style report from Snort fast.log")
    ap.add_argument("--in", dest="in_path", required=True, help="Path to Snort fast.log / alert log")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="Year to inject into Snort timestamps")
    ap.add_argument("--top", type=int, default=10, help="Top N to display")

    # Better defaults for small samples:
    ap.add_argument("--burst-threshold", type=int, default=3, help="Alert count threshold for burst detection")
    ap.add_argument("--burst-window", type=int, default=300, help="Burst time window in seconds")

    args = ap.parse_args(argv)

    print(
        generate_soc_report(
            args.in_path,
            year=args.year,
            top_n=args.top,
            burst_threshold=args.burst_threshold,
            burst_window_seconds=args.burst_window,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
