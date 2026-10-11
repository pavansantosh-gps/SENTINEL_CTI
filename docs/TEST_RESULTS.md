# SENTINEL CTI – TEST RESULTS

## 1. Purpose

This document records the functional testing performed on the SENTINEL CTI full-stack application developed for MongoDB Lab 7.

The testing covered the frontend interface, Flask backend APIs, MongoDB connectivity, CTI search functions, classification, schema analysis, database-performance analysis, and live monitoring.

---

## 2. System Environment

| Component | Used |
|---|---|
| Operating System | Windows |
| Programming Language | Python |
| Backend Framework | Flask |
| Database | MongoDB |
| MongoDB Driver | PyMongo |
| Frontend | HTML, CSS, JavaScript |
| Development Tool | Visual Studio Code |
| Terminal | PowerShell |

---

## 3. Backend Connectivity Test

### MongoDB Connection

The application successfully connected to the local MongoDB server.

Connection:

```text
mongodb://localhost:27017