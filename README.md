# 🛡️ SentinelX — Security Monitoring & Threat Detection

> **A lightweight security monitoring platform that collects authentication events, detects suspicious login behavior, assigns risk scores, and visualizes threats through a modern SOC-style dashboard.**

### 🔐 Key Features

* **📡 Windows Security Log Monitoring**

  * Collects authentication events from Windows Security Logs using Python and PowerShell.
  * Tracks successful and failed login attempts, usernames, timestamps, and source IPs.

* **🔎 Threat Detection**

  * Detects repeated failed login attempts.
  * Identifies multiple usernames targeted from a single IP.
  * Detects **failed login → successful login** patterns.
  * Correlates multiple suspicious behaviors into a single alert.

* **🎯 Risk Scoring**

  * Calculates a **0–100 risk score** based on detected behaviors.
  * Classifies threats as **LOW, MEDIUM, HIGH, or CRITICAL**.

* **🧪 Attack Simulation Lab**

  * Generates safe synthetic security events for testing.
  * Includes Brute Force, Multi-Account Attack, Credential Attack, Failed → Successful Login, and Combined Attack scenarios.
  * **No real attack is performed.**

* **📊 SOC-Style Dashboard**

  * Modern cyber-inspired interface.
  * Authentication activity visualization.
  * Security event monitoring.
  * Threat severity analysis.
  * Security logs and alert history.

* **🕒 Event Timeline**

  * Displays when authentication events occurred.
  * Shows whether each event was **SUCCESS** or **FAILED**.
  * Helps analyze the sequence of suspicious activity.

### ⚙️ Architecture

```text
Windows Security Logs / Attack Simulator
                  ↓
            Log Collection
                  ↓
          Log Normalization
                  ↓
           Detection Engine
                  ↓
             Risk Engine
                  ↓
        0–100 Risk Assessment
                  ↓
     LOW / MEDIUM / HIGH / CRITICAL
                  ↓
         SentinelX Dashboard
```

### 🧰 Tech Stack

```text
Python • Flask • PowerShell
HTML • CSS • JavaScript
Chart.js • CSV
```

---

## 🚀 How to Run SentinelX

### 1. Clone the Repository

```bash
git clone https://github.com/anuragkulk/SentinelX.git
cd SentinelX
```

### 2. Install Dependencies

```bash
py -m pip install flask pandas
```

### 3. Run SentinelX

```bash
py app.py
```

You should see:

```text
============================================================
                 SENTINELX
          SECURITY OPERATIONS CENTER
============================================================

Dashboard:
http://127.0.0.1:5000

Existing simulator.py:
CONNECTED

Security engine:
ACTIVE
============================================================
```

### 4. Open the Dashboard

Open this in your browser:

```text
http://127.0.0.1:5000
```

### 🧪 Running the Attack Simulator

You can also run the simulator directly from the terminal:

```bash
py simulator.py 1
```

Available scenarios:

```text
1 → Brute Force
2 → Multi-Account Attack
3 → Credential Attack
4 → Failed Login → Successful Login
5 → Combined Attack
```

Or simply use the **Threat Simulation** section directly from the SentinelX dashboard.

> **Note:** SentinelX's simulation mode generates synthetic security events for testing the detection engine. It does not perform attacks against the system.

### 📌 Project Purpose

SentinelX is a **hands-on cybersecurity learning project** focused on understanding how authentication events can be collected, normalized, analyzed, correlated, risk-scored, and transformed into actionable security alerts.
