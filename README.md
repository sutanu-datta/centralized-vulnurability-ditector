# 🛡️ seIQrity
### Centralized Vulnerability Detection & Intelligent Query Interface

> A modern AI-powered Vulnerability Assessment and Penetration Testing (VAPT) platform that integrates multiple security scanners into one centralized dashboard.

---

## Overview

Security professionals often rely on multiple standalone tools to perform vulnerability assessments. Managing different outputs from different scanners is inefficient and time-consuming.

**seIQrity** consolidates multiple vulnerability scanners into a unified web platform that automates scanning, normalizes results, correlates vulnerabilities, and provides AI-powered analysis.

---

## Features

- Multi-engine vulnerability scanning
- Nmap Integration
- Nessus Integration *(Planned)*
- OpenVAS Integration *(Planned)*
- Nikto Integration *(In Progress)*
- OWASP ZAP Integration *(Planned)*
- Wapiti Integration *(Planned)*
- Nuclei Integration *(Planned)*
- AI-powered vulnerability explanation
- CVE & CVSS Correlation
- User Authentication
- Scan History
- PDF Report Generation
- REST API
- Responsive Web Dashboard

---

## Tech Stack

### Frontend

- React
- Vite
- Tailwind CSS
- Axios

### Backend

- FastAPI
- Python
- SQLAlchemy
- JWT Authentication

### Database

- SQLite
- PostgreSQL

### Security Tools

- Nmap
- Nikto
- Nessus
- OpenVAS
- OWASP ZAP
- Nuclei
- Wapiti

---

## Architecture

```
Frontend (React)
        │
        ▼
 FastAPI Backend
        │
 ┌──────┼──────────────┐
 │      │      │       │
Nmap  Nikto Nessus OpenVAS ...
        │
        ▼
 Normalization Engine
        │
        ▼
 AI Analysis
        │
        ▼
 Dashboard & Reports
```

---

## Installation

### Clone

```bash
git clone https://github.com/sutanu-datta/centralized-vulnerability-detector.git
```

### Backend

```bash
cd Backend
python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt

uvicorn app:app --reload
```

### Frontend

```bash
cd frontend/cvd-frontend

npm install

npm run dev
```

---

## Roadmap

### Completed

- Project Architecture
- FastAPI Backend
- React Frontend
- Nmap Scanner

### In Progress

- Nikto
- User Authentication
- Database

### Planned

- Nessus
- OpenVAS
- Wapiti
- OWASP ZAP
- AI Chatbot
- Attack Path Visualization
- Threat Intelligence Correlation

---

## Screenshots

*(Coming Soon)*

---

## Future Scope

- Cloud Security
- Docker Scanning
- Kubernetes Security
- Active Directory Auditing
- Threat Intelligence
- Compliance Reports
- SIEM Integration

---

## Contributing

Contributions are welcome!

Fork the repository, create a feature branch, commit your changes, and submit a Pull Request.

---

## License

MIT License

---

## Author

**Sutanu Datta**

Cybersecurity Student | VAPT | Offensive Security | Python | React | FastAPI
