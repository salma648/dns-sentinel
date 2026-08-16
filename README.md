# 🛡️ DNS Sentinel

**Real-Time DNS Threat Detection & Response Platform**

DNS Sentinel is a cybersecurity monitoring platform designed to analyze DNS traffic in real time, detect suspicious behaviors — particularly **DNS Water Torture attacks** — and provide security analysts with monitoring, alerting, and incident-response capabilities through a SOC-style web dashboard.

The project was developed as part of an internship at **Ooredoo Tunisia**.

---

## 🎯 Project Objectives

DNS-based attacks can generate large volumes of apparently legitimate queries while exhausting DNS infrastructure or hiding malicious activity.

DNS Sentinel was designed to build a complete detection pipeline capable of:

- Monitoring DNS traffic in real time
- Detecting DNS Water Torture and Slow Water Torture behaviors
- Analyzing NXDOMAIN responses and query patterns
- Evaluating domain entropy and pseudo-random subdomains
- Generating security alerts with severity levels
- Sending automatic email notifications
- Allowing analysts to manually block or unblock suspicious IP addresses
- Synchronizing the blocklist with PowerDNS
- Providing security analytics through a centralized dashboard

---

## 🏗️ Architecture

```text
                    ┌─────────────────────┐
                    │   DNS Sentinel UI   │
                    │    Flask / HTML     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Detection Engine   │
                    │      Python         │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │       SQLite        │
                    │ Events / Alerts /   │
                    │ Notifications       │
                    └─────────────────────┘

                               ▲
                               │ Real-time monitoring
                               │
                    ┌──────────┴──────────┐
                    │ PowerDNS Recursor   │
                    │     Kali Linux      │
                    └──────────▲──────────┘
                               │ DNS Queries
                               │
                    ┌──────────┴──────────┐
                    │ Docker DNS Clients  │
                    │ Distributed Traffic │
                    └─────────────────────┘
```

The Flask application communicates with the Kali Linux environment through **SSH** to control DNS traffic generation and synchronize PowerDNS configuration.

---

## 🧠 Threat Detection

DNS Sentinel uses behavioral indicators rather than relying on a single signature.

### Water Torture Detection

The detection engine evaluates multiple characteristics including:

- NXDOMAIN response ratio
- Query volume
- Query rate
- Unique subdomain generation
- Domain/subdomain entropy
- Pseudo-random naming patterns
- Source IP behavior
- Time-window based activity
- Multi-factor threat scoring

The platform supports detection of:

- **DNS Water Torture**
- **Slow Water Torture**

The project also includes indicators related to:

- DGA-like domains
- DNS tunneling
- NXDOMAIN bursts
- High-entropy domains
- Pseudo-random subdomains

---

## ⚡ Real-Time DNS Monitoring

DNS events are collected from **PowerDNS Recursor** logs.

The live monitoring component processes information such as:

```text
Source IP
Domain
DNS RCODE
Timestamp
```

Common DNS response codes include:

```text
NOERROR
NXDOMAIN
SERVFAIL
REFUSED
```

Each event is analyzed by the detection engine before being stored in the database.

---

## 📊 SOC Dashboard

DNS Sentinel provides a custom Flask-based security dashboard.

### Overview

The dashboard displays:

- Total DNS events
- Security alerts
- Critical alerts
- Blocked IP addresses
- Alert rate
- Average detection time
- Active notifications

### DNS Events

Analysts can inspect DNS activity including:

- Source IP
- Requested domain
- DNS response code
- Entropy
- Detection time
- Timestamp

### Security Alerts

Detected threats include:

- Attack type
- Severity
- Source IP
- Suspicious domain
- Detection time
- DNS response code

### Analytics

The platform provides security-oriented analytics to help visualize DNS activity and detected threats.

---

## 🚨 Alerting & Notifications

When a **Water Torture** or **Slow Water Torture** attack is detected, DNS Sentinel can automatically:

1. Create a security alert
2. Display a dashboard notification
3. Send an email notification via SMTP

Email notifications contain information such as:

```text
Attack Type
Severity
Source IP
Domain
```

The alert recipient can be configured directly from the administration interface.

---

## 🛡️ Incident Response

Detection and blocking are intentionally separated.

DNS Sentinel automatically detects threats, while the final blocking decision remains under analyst control.

From the dashboard, an analyst can:

```text
Detect suspicious IP
        ↓
Review security alert
        ↓
Block IP manually
        ↓
Update SQLite blocklist
        ↓
Synchronize PowerDNS Lua blocklist
        ↓
PowerDNS refuses requests from blocked source
```

Blocked clients receive DNS responses with:

```text
REFUSED
```

An analyst can later **unblock** the address from the dashboard.

This approach keeps a human decision in the incident-response workflow and reduces the impact of potential false positives.

---

## 🔐 Administration

Access to DNS Sentinel is protected through an administrator authentication system.

The administration interface allows the administrator to:

- Authenticate before accessing the platform
- Modify administrator credentials
- Configure the email address receiving security alerts
- Access detection settings
- Log out securely

---

## 🐳 DNS Traffic Simulation

DNS traffic is generated through multiple **Docker containers** running on Kali Linux.

This provides several independent source IP addresses and allows the platform to analyze distributed DNS behavior.

Traffic generation can be controlled directly from the dashboard:

- **Generate DNS Traffic**
- **Stop DNS Traffic**
- **Reset Demo Data**

---

## 🔄 PowerDNS Integration

PowerDNS Recursor is used as the DNS infrastructure monitored by DNS Sentinel.

A Lua-based blocklist is dynamically synchronized with the platform.

Example:

```lua
blocked_ips = {
    ["172.18.0.5"] = true,
}
```

When a blocked client sends another DNS request, PowerDNS can reject it with a `REFUSED` response.

---

## 🗄️ Data Storage

DNS Sentinel uses **SQLite** to store platform data.

Main data categories include:

- DNS events
- Security alerts
- Notifications
- Blocked IP addresses
- Application settings

This allows the dashboard and detection components to share a centralized source of information.

---

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, Flask |
| DNS Infrastructure | PowerDNS Recursor |
| Detection | Python behavioral analysis |
| Database | SQLite |
| Containers | Docker, Docker Compose |
| Security Environment | Kali Linux |
| Remote Management | SSH |
| Automation | Bash |
| DNS Policy | Lua |
| Monitoring | journalctl |
| Notifications | SMTP |
| Frontend | HTML, CSS, Jinja2 |
| Version Control | Git, GitHub |

---

## 📁 Project Structure

```text
dns-sentinel/
│
├── app.py
├── config.py
├── database.py
├── detector.py
├── storage.py
│
├── powerdns_live_monitor.py
├── powerdns_import.py
├── powerdns_reader.py
├── powerdns_stats.py
│
├── blocklist_manager.py
├── docker_controller.py
├── notifier.py
│
├── report.py
├── pdf_report.py
│
├── static/
│   └── style.css
│
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   ├── events.html
│   ├── alerts.html
│   ├── alert_detail.html
│   ├── analytics.html
│   ├── blocklist.html
│   ├── reports.html
│   └── settings.html
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

## ⚙️ Requirements

The project requires:

- Python 3
- Flask
- SQLite
- Kali Linux
- Docker / Docker Compose
- PowerDNS Recursor
- SSH connectivity between the application host and Kali Linux

Install Python dependencies with:

```bash
pip install -r requirements.txt
```

---

## 🔑 Environment Variables

Sensitive credentials should **never be committed to GitHub**.

For example, the SMTP password should be provided through an environment variable:

```text
EMAIL_PASSWORD
```

The application reads it using:

```python
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
```

---

## 🚀 Running the Application

Initialize the database:

```bash
python database.py
```

Start DNS Sentinel:

```bash
python app.py
```

Then access the Flask interface from the browser.

The Kali Linux environment must have the required PowerDNS, Docker and SSH configuration for the complete lab architecture to operate.

---

## 🔬 Detection Workflow

```text
Docker DNS Clients
        │
        ▼
PowerDNS Recursor
        │
        ▼
PowerDNS Logs
        │
        ▼
Real-Time Python Monitor
        │
        ▼
Behavioral Detection Engine
        │
        ├──── Normal Traffic ────► DNS Events
        │
        └──── Threat Detected
                  │
                  ▼
             Security Alert
                  │
          ┌───────┴────────┐
          ▼                ▼
     Dashboard          Email Alert
          │
          ▼
     Analyst Review
          │
          ▼
      Block / Unblock
          │
          ▼
   PowerDNS Lua Blocklist
```

---

## 💡 Key Learning Outcomes

This project provided practical experience in:

- DNS security monitoring
- Behavioral threat detection
- DNS Water Torture attack analysis
- Real-time log processing
- PowerDNS administration
- Docker-based traffic simulation
- Linux security environments
- Python security automation
- SOC-oriented dashboard development
- Security alerting
- Incident response workflows
- IP blocklist management
- Integration between Windows and Kali Linux environments

---

## ⚠️ Disclaimer

DNS Sentinel was developed for **educational, research and controlled laboratory purposes**.

Traffic simulation and security testing should only be performed on systems and networks for which explicit authorization has been granted.

---

## 👩‍💻 Author

**Salma Younes**

Cybersecurity project developed during an internship at **Ooredoo Tunisia**.

---

## 📄 License

This project is intended primarily for educational and research purposes.
