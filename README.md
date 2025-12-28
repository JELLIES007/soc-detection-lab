# SOC Detection Lab

A hands-on Security Operations Center (SOC) lab focused on intrusion detection,
log parsing, alert validation, and analyst-ready data structures.

This project demonstrates practical blue-team engineering skills by working
with real IDS alert data and building tooling that supports detection,
triage, and incident response workflows.

---

## 🎯 Project Goals

- Work with **real Snort IDS alert logs**
- Parse and normalize alert data into structured fields
- Validate alert integrity using **test-driven development**
- Lay the foundation for SOC ingestion, enrichment, and analysis pipelines
- Practice professional documentation and repository hygiene

---

## 🧱 Architecture Overview

```text
Snort IDS
   ↓
fast.log (raw alerts)
   ↓
Python Parser
   ↓
Normalized Alert Objects
   ↓
Validation (pytest)
   ↓
SOC / SIEM-ready output
