# 🛡️ SentinelX — Security Monitoring & Threat Detection

> **A lightweight security monitoring platform that collects authentication events, detects suspicious login behavior, assigns risk scores, and visualizes threats through a modern SOC-style dashboard.**

### 🔐 Key Features

* **📡 Windows Security Log Monitoring**

  * Collects authentication events from Windows Security Logs using Python and PowerShell.
  * Tracks successful and failed login attempts, usernames, timestamps, and source IPs.

* **🔎 Intelligent Threat Detection**

  * Detects repeated failed login attempts.
  * Identifies multiple usernames being targeted from a single IP.
  * Detects **failed-login → successful-login** patterns.
  * Correlates multiple suspicious behaviors into a single alert.

* **🎯 Risk Scoring Engine**

  * Calculates a **0–100 security risk score** based on detected behaviors.
  * Categorizes alerts into:

    * 🟢 LOW
    * 🟡 MEDIUM
    * 🟠 HIGH
    * 🔴 CRITICAL

* **🧪 Attack Simulation Lab**

  * Generates safe, synthetic security events for testing.
  * Includes scenarios such as:

    * Brute Force
    * Multi-Account Attack
    * Credential Attack
    * Failed → Successful Login
    * Combined Attack
  * **No real attack is performed.**

* **📊 SOC-Style Dashboard**

  * Modern dark/light cyber-inspired interface.
  * Real-time overview of authentication activity.
  * Security event visualization.
  * Threat severity charts.
  * Security log viewer.
  * Alert history and investigation data.

* **🕒 Security Event Timeline**

  * Displays when authentication events occurred.
  * Shows whether each request resulted in **SUCCESS** or **FAILED**.
  * Preserves the sequence of suspicious activity for analysis.

* **📝 Alert History**

  * Stores detected threats for later review.
  * Provides information such as source IP, usernames, detections, risk score, severity, and timestamps.

### ⚙️ How It Works

```text
Windows Security Logs
        │
        ▼
   Log Collection
        │
        ▼
  Log Normalization
        │
        ▼
  Detection Engine
        │
        ▼
    Risk Engine
        │
        ▼
  0–100 Risk Score
        │
        ▼
LOW / MEDIUM / HIGH / CRITICAL
        │
        ▼
   SentinelX Dashboard
```

### 🧰 Tech Stack

```text
Python
Flask
PowerShell
HTML / CSS / JavaScript
Chart.js
CSV-based Storage
```

> **SentinelX is built as a hands-on cybersecurity project to understand how authentication logs can be collected, analyzed, correlated, and transformed into meaningful security alerts.**
