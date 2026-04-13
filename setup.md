# CHEQ Automated Threat Mitigation Pipeline — Setup Guide

## Prerequisites

- Python 3.8+
- A terminal

## Installation

Clone this git repo: https://github.com/LukeFasanello/cheq-takehome

cd into the project directory:

```bash
cd cheq-takehome
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Pipeline

```bash
python pipeline.py
```

This will:
1. Fetch live traffic data from the CHEQ endpoint (solves the JS bot challenge automatically)
2. Run detection rules across all sessions and assign risk scores
3. Write three output files to the project root:
   - `results.json` — all sessions enriched with `risk_score` and `verdict`
   - `blocked_ips.json` — confirmed bot IPs and timestamp
   - `summary.json` — pre-aggregated KPIs for the dashboard

## Viewing the Dashboard

The dashboard reads `summary.json` via `fetch()`, which requires a local HTTP server (browsers block filesystem reads for security reasons).

Start the server from the project root:

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000` in your browser.

To stop the server:

```bash
lsof -ti:8000 | xargs kill
```

## Scheduling (Production)

The pipeline is structured around a single `run()` function, making it trivially schedulable. To run it every hour via cron:

```bash
0 * * * * /path/to/venv/bin/python /path/to/pipeline.py
```

## Notes on Data Fetching

The CHEQ data endpoint is protected by a JavaScript bot challenge. The pipeline solves this automatically by extracting the AES key, IV, and ciphertext from the challenge response, decrypting the cookie value in Python using `pycryptodome`, and replaying the authenticated request. No manual steps required.

## Project Structure

```
cheq-threat-pipeline/
├── pipeline.py               # Core detection and remediation engine
├── index.html                # Proof of Value dashboard
├── requirements.txt          # Python dependencies
├── setup.md                  # This file
├── results.json              # Generated — enriched session data
├── blocked_ips.json          # Generated — blocked IP list
└── summary.json              # Generated — dashboard KPIs
```
