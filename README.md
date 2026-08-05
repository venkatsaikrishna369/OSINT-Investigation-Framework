# OSINT Investigation Framework

## A Complete Passive Intelligence Gathering Tool

This framework helps security professionals, bug bounty hunters, and penetration testers gather and analyze publicly available information about any domain. It transforms scattered data points into actionable security intelligence.

---

## What It Does

This tool performs a complete passive OSINT investigation by:

1. **Collecting WHOIS Data** - Domain registration details, age, expiry
2. **Mapping DNS Infrastructure** - A, AAAA, MX, NS, TXT, CAA records
3. **Analyzing IP & Hosting** - ASN, geolocation, hosting provider
4. **Examining SSL Certificates** - Issuer, validity, cipher suites
5. **Checking Security Headers** - CSP, HSTS, X-Frame-Options and more
6. **Fingerprinting Technologies** - Web servers, frameworks, libraries
7. **Discovering Subdomains** - Via certificate transparency and DNS
8. **Scanning robots.txt & Sitemap** - For exposed paths
9. **Correlating Intelligence** - Building a complete picture
10. **Assessing Risk** - Scoring and prioritizing findings
11. **Generating Reports** - Professional HTML with PDF export

---

## How It Works

The framework follows an intelligence lifecycle:
Target
   ↓
Domain OSINT
   ↓
DNS OSINT
   ↓
Web OSINT
   ↓
Certificate OSINT
   ↓
Technology OSINT
   ↓
Subdomain Discovery
   ↓
Correlation
   ↓
Risk Assessment
   ↓
Professional Report


Each phase builds on the previous one, creating a complete intelligence profile.

---

## Installation

### Requirements
- Python 3.8 or higher
- pip (Python package manager)
- Internet connection

### Quick Setup

```bash
# Clone or download the repository
git clone https://github.com/venkatsaikrishna369/OSINT-Investigation-Framework.git
cd OSINT-Investigation-Framework

# Install dependencies
pip install -r requirements.txt

# Run an investigation
python src/osint_framework_final.py example.com




### Run a Basic Investigation

```bash

python src/osint_framework_final.py chicken-road2.app
```

### View the Report

1. Open `reports/osint_report.html` in your web browser.
2. Click the **Download PDF** button in the top-right corner.
3. Check `reports/intelligence.json` for the raw investigation data.

## Sample Output

```text
[START] OSINT Investigation for example.com
============================================================
[Phase 1] Target Definition
[Phase 2] Domain Intelligence
  -> Domain registration collected (Age: 1,245 days)
[Phase 3] DNS Intelligence
  -> DNS records collected: 7 types
[Phase 4] IP & ASN Intelligence
  -> IP intelligence collected for 2 addresses
[Phase 5] SSL/TLS Intelligence
  -> SSL certificate collected (Expires in 156 days)
[Phase 6] Security Headers Analysis
  -> Security headers collected (Score: 67%)
[Phase 7] Technology Fingerprinting
  -> Technologies detected: 12
[Phase 8] Subdomain Discovery
  -> Subdomains discovered: 8 from 2 sources
[Phase 9] Web Content Analysis
  -> Web content analyzed
[Phase 10] robots.txt & Sitemap
  -> robots.txt found with 4 disallowed paths
[Phase 11] Additional OSINT
  -> Additional OSINT collected
[Phase 12] Intelligence Correlation
  -> Intelligence correlated (5 observations)
[Phase 13] Risk Assessment
  -> Risk assessment: MEDIUM (Score: 45)
[Phase 14] Timeline Generation
  -> Timeline generated with 3 events
[Phase 15] Report Generation
  -> HTML report saved: reports/osint_report.html
  -> PDF report saved: reports/osint_report.pdf
  -> JSON data saved: reports/intelligence.json

[COMPLETE] Investigation Complete!
```

---

## Understanding the Report

### Intelligence Dashboard

The dashboard provides an instant overview of the investigation, including:

* Number of IP addresses discovered
* DNS records found
* Subdomains identified
* Security findings
* Timeline events
* Overall risk assessment

### Risk Assessment

The tool calculates a risk score based on multiple security observations:

* **SSL Certificate** - Expiry dates, with higher scores for certificates expiring soon
* **Security Headers** - Missing security headers and their associated risk
* **Attack Surface** - Number of discovered subdomains
* **Sensitive Paths** - Potentially sensitive paths exposed through `robots.txt`

### Recommendations

Based on the investigation findings, the framework provides actionable recommendations such as:

* Implement missing security headers
* Renew SSL certificates before expiration
* Review exposed paths
* Monitor discovered subdomains

---

## Project Structure

```text
OSINT-Investigation/
│
├── src/
│   └── osint_framework_final.py    # Main investigation script
│
├── reports/                        # Generated reports
│   ├── osint_report.html          # Interactive HTML report
│   ├── osint_report.pdf           # PDF export
│   └── intelligence.json          # Raw JSON data
│
├── sources/                        # Source documentation
│   └── source_registry.csv        # Traceability of all data sources
│
├── requirements.txt                # Python dependencies
├── README.md                       # Project documentation
└── .gitignore                      # Git ignore rules
```
