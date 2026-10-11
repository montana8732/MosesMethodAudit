# Enterprise Compliance & Cryptographic Audit Ledger Engine

Developed by **The Moses Method Structures, LLC**

## Architectural Overview
A high-throughput local compliance governance and log-auditing engine built with Python and Flask. The system performs real-time automated redaction for sensitive healthcare and financial identifiers (SSN, NPI, ICD-10, MRN, PHI) while logging all audit events to an immutable SHA-256 cryptographic hash-chained ledger (`audit_ledger.db`).

## Core Capabilities
* **Automated Redaction Engine:** Regex-based multi-pattern scanner for regulatory healthcare compliance.
* **Cryptographic Tamper Detection:** Forward hash chaining ($H_n = \text{SHA256}(ID \parallel TS \parallel Payload \parallel H_{n-1})$) detects out-of-band database alterations instantly.
* **Self-Healing Ledger Repair:** Administrative re-signing pipeline to validate and restore corrupted ledger links.
* **Role-Based Governance Analytics:** Real-time Chart.js dashboard tracking violation breakdowns, audit pass rates, and dynamic actor activities.

## Technology Stack
* **Backend:** Python 3, Flask, SQLite3, Hashlib, Regex
* **Frontend:** HTML5, CSS3, JavaScript (ES6+), Chart.js
* **DevOps & Scripting:** PowerShell Automation
