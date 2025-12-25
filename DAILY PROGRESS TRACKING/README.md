# SOC Detection Lab

A structured, test-driven SOC detection lab focused on parsing and normalizing **Snort fast alert logs** into SIEM-ready data structures.  
This project emphasizes correctness, resilience to real-world alert variations, and professional SOC engineering practices.

---

## 📌 Project Overview

The **SOC Detection Lab** is designed to simulate a real-world detection pipeline component by ingesting Snort fast alerts, parsing them reliably, and converting them into structured, normalized alert objects suitable for SIEM ingestion (ELK, Splunk, SOAR tools).

Key goals:
- Robust parsing of Snort fast alert format
- Support for IPv4 and IPv6 traffic
- Graceful handling of protocol differences (TCP, UDP, ICMP)
- Test-driven development with pytest
- Clean, scalable Python project structure

---

## 📁 Project Structure


### Folder Breakdown
- **`src/`** – Application source code
- **`src/parsers/snort_fast.py`** – Snort fast alert parser implementation
- **`tests/`** – Automated test suite
- **`venv/`** – Python virtual environment
- **`pytest.ini`** – Pytest configuration
- **`.pytest_cache/` / `__pycache__/`** – Runtime caches
- **`README.md`** – Project documentation

---

## 🐍 Environment Setup

A Python virtual environment was created to ensure:
- Dependency isolation
- Reproducible testing
- Clean separation from system Python

All development and testing is performed inside the virtual environment.

---

## 🚨 Snort Fast Alert Parser

### Parser Location

### Implemented Features
The parser supports:
- Snort fast alert format
- IPv4 and IPv6 addresses
- TCP, UDP, and ICMP protocols
- Optional ports (ICMP / no-port alerts)
- Priority-to-severity normalization
- Immutable alert objects using dataclasses
- JSON and dictionary serialization for SIEM ingestion

### Core Functions
- `parse_fast_line()` – Parse a single alert line
- `parse_fast_file()` – Stream-parse alert files safely
- `priority_to_severity()` – Normalize Snort priority values

### Alert Object
Alerts are represented using a frozen dataclass:

- Timestamp
- GID / SID / Revision
- Message
- Priority and SOC-style severity
- Protocol
- Source and destination IPs
- Optional ports
- Tool identifier (`snort`)

---

## 🔍 Regex Hardening & Edge Case Handling

The parser regex was hardened to support real SOC conditions:
- IPv4 and IPv6 compatibility
- Optional port fields
- ICMP alerts without ports
- Correct handling of literal braces in f-strings
- Backward compatibility with IPv4-only alerts

This ensures the parser does not fail on common real-world alert variations.

---

## 🧪 Testing (pytest)

### Test Coverage
The test suite validates:
- Priority-to-severity mapping
- TCP alert parsing
- UDP alert parsing
- ICMP alert parsing (no ports)
- IPv6 alert parsing
- Blank and malformed line handling

### Test File

### Pytest Configuration
A `pytest.ini` file ensures:
- Project root is on `PYTHONPATH`
- `src/` imports resolve correctly
- Tests are discovered under `tests/`

---

## ✅ Test Results

Final test run:

```bash
pytest -q
5 passed in 0.02s
