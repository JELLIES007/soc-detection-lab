# SOC Detection & Response Pipeline with Adversary TTP Analysis
Bridges the gap between raw IDS alerts and SOC analyst workflows through structured parsing, enrichment, and detection logic.

A hands-on Security Operations Center (SOC) lab focused on intrusion detection, log parsing, alert validation, and analyst-ready data structures.

This project demonstrates practical blue-team engineering skills by working with real IDS alert data and building tooling that supports detection, triage, and incident response workflows.


## Key Features

- IDS log parsing and normalization
- Alert enrichment and severity mapping
- Time-windowed alert grouping (case simulation)
- MITRE ATT&CK mapping (foundational)
- Analyst-ready output formats

## Progression phases in development
- Built a full detection pipeline to parse Snort fast.log into structured JSONL for SIEM-ready ingestion
- Designed normalization and enrichment logic (severity mapping, protocol handling, IP context) to improve alert clarity and usability
- Implemented time-windowed alert grouping to simulate real SOC case creation and reduce alert fatigue
- Generated analyst-focused outputs including grouped alerts and top talker summaries for rapid triage
- Integrated foundational MITRE ATT&CK mapping to align detections with adversary TTPs
Structured outputs for compatibility with platforms like Splunk and Elastic Stack

---

## Pipeline Overview

Snort Alerts (fast.log)
        ↓
Parsing (parse_snort_file)
        ↓
Normalization (normalize_snort_event)
        ↓
Enrichment (severity, protocol, context)
        ↓
Grouping (time-windowed case creation)
        ↓
Output (JSONL, grouped alerts, summaries)

## Running the Pipeline

python3 -m src.pipeline

Outputs:
- out/events.jsonl
- out/groups.json
- out/top_talkers.json

## Security Note

Certain detection logic, correlation thresholds, and response strategies are intentionally abstracted to prevent misuse or evasion. This repository demonstrates architecture and workflow without exposing sensitive defensive mechanisms.

## Example Output (events.jsonl)

{
  "timestamp": "...",
  "src_ip": "...",
  "dst_ip": "...",
  "protocol": "TCP",
  "severity": "high",
  "signature": "ET SCAN Potential SSH Scan"
}

---

## 🎯 Project Goals

- Work with **real Snort IDS alert logs**
- Parse and normalize alert data into structured fields
- Validate alert integrity using **test-driven development**
- Lay the foundation for SOC ingestion, enrichment, and analysis pipelines
- Practice professional documentation and repository hygiene

---

## Detection & Investigation Capabilities

- Correlates network and host-based indicators to identify suspicious behavior patterns across multiple attack vectors
- Enriches alerts with contextual indicators including source behavior, access patterns, and protocol anomalies
- Establishes behavioral baselines to detect deviations such as unusual login locations, abnormal access times, or irregular network traversal
- Identifies indicators associated with common attack techniques including unauthorized access attempts, credential misuse, privilege escalation, lateral movement, and anomalous authentication activity
- Detects reconnaissance behaviors such as port scanning, enumeration, and banner grabbing, including low-and-slow or stealth scanning patterns
- Flags indicators of potential man-in-the-middle activity, proxy/VPN usage anomalies, and irregular key exchange behavior when observable in logs
- Captures and prioritizes events associated with potential phishing-related activity or abnormal user interactions with suspicious resources
- Aggregates and records detailed event metadata to support incident investigation and escalation workflows
- Prioritizes high-risk anomalies and routes them for analyst review based on severity and deviation from expected behavior

---

## Escalation & Response Workflow

- Automatically escalates high-severity or unclassified anomalies for manual analyst review
- Flags events lacking sufficient context for deeper investigation and correlation
- Supports incident response workflows including containment recommendations such as isolating affected systems or initiating controlled analysis environments
- Enables integration with sandboxing or controlled test environments for safe analysis of suspicious activity
- Provides structured output to support reporting, documentation, and handoff to incident response teams

---

## Deception and Controlled Interaction Layer

- Implements decoy artifacts and simulated assets to attract adversary interaction in a controlled environment
- Supports observation of attacker behavior, techniques, and progression without exposing production systems
- Enables collection of behavioral data to improve detection tuning and reduce false positives
- Differentiates between high-severity incidents requiring immediate containment and lower-risk interactions suitable for behavioral analysis
- Designed for integration with isolated environments (e.g., segmented networks or DMZs) to ensure safe observation and containment
- Supports development of enhanced detection logic based on observed adversary techniques and patterns

---
