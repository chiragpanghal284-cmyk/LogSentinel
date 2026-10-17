# 🛡️ LogSentinel — Security Log Analyzer

> A cybersecurity portfolio project for detecting suspicious authentication activity from CSV log files.

**⚠️ Disclaimer:** This tool is for **educational purposes only**. It does not connect to real systems, scan external IP addresses, or collect real credentials. A flagged IP address does **not** automatically prove an attack — it indicates a pattern that warrants investigation by a qualified security analyst.

---

## 📋 Features

| Feature | Details |
|---|---|
| **CSV log upload** | Drag-and-drop authentication log files |
| **Automatic validation** | Checks required columns, timestamps, and format |
| **Brute-force detection** | Rolling-window algorithm, configurable threshold & window |
| **Multi-username detection** | Flags credential-stuffing patterns |
| **Severity classification** | LOW / MEDIUM / HIGH / CRITICAL |
| **Dashboard metrics** | Total events, failed/success logins, unique IPs, alert counts |
| **Interactive visualizations** | Login outcomes over time, top IPs, severity breakdown, top usernames |
| **Log Explorer** | Filter raw logs by status, event type, or IP address |
| **CSV export** | Download the generated alert report |
| **Built-in sample dataset** | Fictional authentication events for instant demonstration |
| **Graceful error handling** | Missing values, bad timestamps, and malformed CSVs handled safely |

---

## 🏗️ Project Architecture

```
LogSentinel/
├── app.py                     ← Streamlit web UI (display only, no detection logic)
├── detector.py                ← Detection engine (pure Python, no UI dependencies)
├── requirements.txt           ← Python dependencies
├── README.md                  ← This file
├── data/
│   └── sample_auth_logs.csv  ← Fictional sample dataset (80 events)
└── tests/
    ├── __init__.py
    └── test_detector.py       ← 22 automated unit tests
```

**Key architectural decision:** Detection logic (`detector.py`) is fully separated from the user interface (`app.py`). This makes the logic independently testable and reusable.

---

## ⚙️ Installation

### Prerequisites
- Python 3.9 or newer
- pip

### Steps

```bash
# 1. Clone or download this project to your machine
cd LogSentinel

# 2. (Recommended) Create a virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Running the Application

```bash
streamlit run app.py
```

The application will open automatically at `http://localhost:8501` in your browser.

On first launch, it displays results for the built-in **sample dataset** — no upload required. Use the sidebar to upload your own CSV file.

---

## 📂 CSV Log Format

Your log file must be a CSV with **at least these five columns** (case-insensitive):

| Column | Description | Example |
|---|---|---|
| `timestamp` | ISO-8601 datetime | `2024-06-15 08:07:45` |
| `ip_address` | Source IP address | `192.168.1.100` |
| `username` | Username that was attempted | `alice` |
| `event_type` | Type of event | `login` |
| `status` | Outcome | `failed` or `success` |

Extra columns (e.g. `user_agent`, `location`) are accepted and displayed but not used for detection.

**Recognised event types:** `login`, `authentication`, `auth`  
**Recognised failure statuses:** `failed`, `failure`, `fail`  
**Recognised success statuses:** `success`, `ok`

---

## 🔍 Detection Algorithm

LogSentinel uses a **rolling-window brute-force detection** rule:

1. Filter to `login`/`authentication` events where `status` is `failed`.
2. Group by `ip_address`.
3. For each group, slide a time window of configurable width (default **10 minutes**) forward through the sorted event list.
4. If the count of failed events inside the window reaches or exceeds the threshold (default **5**), raise an alert and advance past the burst.
5. Classify severity:

| Severity | Trigger |
|---|---|
| LOW | ≥ 1× threshold |
| MEDIUM | ≥ 1.5× threshold |
| HIGH | ≥ 2× threshold |
| CRITICAL | ≥ 4× threshold |

If attempts span multiple usernames, the reason note includes a **credential stuffing** warning.

---

## ⚠️ Limitations

- **False positives:** Legitimate users on shared networks or misconfigured apps can generate high failure counts.
- **No distributed detection:** Attacks that use many different IPs (botnets) each contributing a few attempts will not be flagged.
- **No geo-intelligence:** Internal (RFC-1918) addresses are treated identically to public ones.
- **Read-only:** The tool does not modify any system, lock any account, or write to any log.
- **Static dataset:** The detection window is per-file; it has no memory of previous uploads.

---

## 🧪 Running Tests

```bash
# From the project root
pytest tests/test_detector.py -v
```

The test suite covers:
- CSV validation (missing columns, empty files, bad timestamps, case-insensitive columns)
- Data cleaning (sorting, dropping bad rows, filling missing values)
- Detection correctness (threshold triggering, window boundaries, multiple IPs, multiple bursts)
- Severity classification (LOW → CRITICAL)
- Multi-username / credential-stuffing detection
- Edge cases (empty input, threshold = 1, custom window sizes)
- `alerts_to_dataframe` output structure and content

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web application framework |
| `pandas` | CSV parsing and data manipulation |
| `altair` | Declarative charts and visualizations |
| `pytest` | Automated test runner |

---

## 🎓 About This Project

LogSentinel was built as a cybersecurity bootcamp portfolio project demonstrating:
- Separation of concerns (detection engine vs. UI)
- Transparent, explainable detection rules
- Responsible disclosure practices (no real IP scanning, no credential collection)
- Automated testing of security logic
- Clean, professional dashboard design

**Author:** Cybersecurity Bootcamp Student  
**Purpose:** Portfolio / educational demonstration  
**Real-world applicability:** The rolling-window brute-force pattern is similar to rules used in production SIEM tools (e.g. Splunk, Elastic SIEM), though production systems add far more context, correlation, and tuning.
