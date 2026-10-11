# SENTINEL CTI

## Cyber Threat Intelligence Monitoring and Analysis Platform

SENTINEL CTI is a full-stack Cyber Threat Intelligence (CTI) platform developed using MongoDB, Python, Flask, HTML, CSS, and JavaScript.

The platform combines the activities of **Lab 7.1 – Production Schema Analysis** and **Lab 7.2 – Working Set Analysis** into one working application.

---

## 1. Project Overview

SENTINEL CTI provides a centralized interface for exploring cyber threat information, analyzing MongoDB data design, evaluating database performance, and monitoring security-report sources.

The platform provides:

- Threat Indicator search for IP addresses, domains, URLs, and hashes
- Threat intelligence search and filtering
- Security report search
- Explainable threat classification
- MongoDB schema analysis
- BSON document-size analysis
- Embedded versus referenced data analysis
- Working-set performance analysis
- WiredTiger cache monitoring
- Random-read workload testing
- Live security-report source monitoring

---

## 2. Meaning of SENTINEL CTI

**SENTINEL** represents a system that observes and monitors activity.

**CTI** stands for **Cyber Threat Intelligence**.

Therefore:

> SENTINEL CTI represents a Cyber Threat Intelligence monitoring and analysis platform.

---

## 3. Objectives

### Lab 7.1 – Analyze a Production Schema

The objectives are to:

1. Examine a realistic CTI-style MongoDB schema.
2. Identify relationships implemented using embedding and referencing.
3. Explain why references are used for shared or independently managed information.
4. Analyze MongoDB BSON document sizes using `$bsonSize`.
5. Verify that documents remain safely below MongoDB's 16 MiB BSON document limit.
6. Redesign a referencing relationship using an embedded representation.

### Lab 7.2 – Working Set Analysis

The objectives are to:

1. Insert 100,000 test documents of approximately 2 KB each.
2. Estimate the working-set size.
3. Inspect WiredTiger cache information using `serverStatus`.
4. Perform random reads across the working-set collection.
5. Observe cache-related metrics during repeated reads.
6. Monitor a public security-report source at regular intervals.
7. Record monitoring results every 10 seconds.

---

## 4. Technologies Used

### Backend
- Python
- Flask
- PyMongo
- Requests
- BeautifulSoup
- Flask-CORS

### Frontend
- HTML5
- CSS3
- JavaScript

### Database
- MongoDB
- WiredTiger storage engine

### Tools
- Visual Studio Code
- MongoDB Shell
- PowerShell

---

## 5. Project Structure

```text
SENTINEL_CTI/
│
├── backend/
│   ├── app.py
│   ├── database.py
│   │
│   ├── routes/
│   │   ├── analytics.py
│   │   ├── classification.py
│   │   ├── iocs.py
│   │   ├── live_reports.py
│   │   ├── monitoring.py
│   │   ├── reports.py
│   │   ├── schema.py
│   │   └── threats.py
│   │
│   └── services/
│       ├── cache_monitor.py
│       ├── classification.py
│       └── schema_analysis.py
│
├── frontend/
│   ├── index.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── app.js
│
├── lab_7_1/
│   ├── production_schema.py
│   └── embedded_redesign.py
│
├── lab_7_2/
│   ├── working_set_analysis.py
│   └── live_monitor.py
│
├── data/
│   ├── build_cti_seed.py
│   ├── cti_7_1_seed.json
│   ├── import_security_reports.py
│   ├── security_reports_source.json
│   ├── lab_7_2_results.json
│   └── live_monitor_log.jsonl
│
├── docs/
│
├── .env
├── .gitignore
├── requirements.txt
└── README.md