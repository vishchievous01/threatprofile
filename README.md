# ThreatProfile

**An automated threat intelligence aggregator that builds a complete attacker profile from a single IP address — replacing 20-30 minutes of manual OSINT across multiple tools with one API call.**

## The Problem

When a SOC analyst investigates a suspicious IP, they typically open 8-10 separate tools — VirusTotal, AbuseIPDB, Shodan, NVD, MITRE ATT&CK — and manually piece together a picture of the threat. This is slow, repetitive, and doesn't scale.

## The Solution

ThreatProfile takes an IP address and automatically:
1. Queries AbuseIPDB, VirusTotal, and Shodan (InternetDB) in parallel
2. Merges the results into a single structured profile
3. Maps observed indicators (tags, behavior) to MITRE ATT&CK techniques
4. Persists the profile to a database, so previously-seen attackers are recognized instantly on future lookups
5. Exposes everything through a REST API

Instead of asking *"Is this IP malicious?"*, it answers *"Who is this attacker, and what have they done?"*

## Example Output

```json
{
  "ip_address": "185.220.101.1",
  "country": "DE",
  "isp": "Stiftung Erneuerbare Freiheit",
  "org": "Stiftung Erneuerbare Freiheit",
  "abuse_score": 100,
  "total_reports": 342,
  "vt_malicious_votes": 14,
  "vt_suspicious_votes": 2,
  "vt_reputation": -22,
  "open_ports": [22, 9001],
  "hostnames": [],
  "techniques": [
    {
      "technique_id": "T1090.003",
      "name": "Multi-hop Proxy",
      "tactic": "command-and-control",
      "description": "Adversaries may chain together multiple proxies..."
    }
  ]
}
```

## Architecture

```
                    ┌─────────────────┐
   IP Address ─────▶│  Django REST API │
                    └────────┬─────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
     AbuseIPDB          VirusTotal      Shodan (InternetDB)
   (reputation,       (detection,        (open ports,
    report count)      tags, ASN)         hostnames)
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
                    ┌─────────────────┐
                    │  Merge Engine    │
                    └────────┬─────────┘
                             ▼
                    ┌─────────────────┐
                    │ MITRE ATT&CK     │
                    │ Tag → Technique  │
                    │ Mapping          │
                    └────────┬─────────┘
                             ▼
                    ┌─────────────────┐
                    │  PostgreSQL/     │
                    │  SQLite DB       │
                    └────────┬─────────┘
                             ▼
                    ┌─────────────────┐
                    │  REST API        │
                    │  Response (JSON) │
                    └─────────────────┘
```

## Tech Stack

- **Backend:** Django, Django REST Framework
- **Database:** SQLite (dev) / PostgreSQL (production-ready)
- **Threat Intel Sources:** AbuseIPDB API, VirusTotal API, Shodan InternetDB
- **Technique Mapping:** MITRE ATT&CK Enterprise (STIX/JSON dataset)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/lookup/` | Runs a full lookup on a new IP and saves the profile |
| `GET`  | `/api/attacker/<ip>/` | Retrieves a previously-saved attacker profile |
| `GET`  | `/api/attackers/` | Lists all saved attacker profiles |

### Example Request
```bash
curl -X POST http://127.0.0.1:8000/api/lookup/ \
  -H "Content-Type: application/json" \
  -d '{"ip": "185.220.101.1"}'
```

## Setup

```bash
git clone https://github.com/<your-username>/threatprofile.git
cd threatprofile
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:
```
ABUSEIPDB_KEY=your_key_here
VT_KEY=your_key_here
```

Download the MITRE ATT&CK dataset (used for technique mapping, ~47MB, not tracked in git):
```bash
curl -o intel/mitre_data.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Run migrations and start the server:
```bash
python manage.py migrate
python manage.py runserver
```

## How This Was Built

This project was built incrementally over 4 focused sessions:
1. **Django project setup + AbuseIPDB integration** — single-source IP lookup, saved to DB
2. **Multi-source merge** — added VirusTotal and Shodan, unified into one profile
3. **MITRE ATT&CK mapping** — parsed the full ATT&CK dataset and built a rule-based tag-to-technique mapping
4. **REST API** — exposed the pipeline through Django REST Framework endpoints

## Roadmap

- [ ] CVE correlation based on detected open ports/services
- [ ] React frontend with search + attacker profile card
- [ ] Relationship graph (IP ↔ malware ↔ campaign ↔ CVE)
- [ ] Deployed live demo (Render/Railway)

## Why I Built This

As a SOC analyst candidate, I wanted to demonstrate practical understanding of threat intelligence workflows — not just theory. This project mirrors what real SOC tooling does: aggregating multiple OSINT sources into a single, actionable attacker profile, with MITRE ATT&CK context to support triage and incident response decisions.

---

**Author:** Vishnu | EC-Council CSA Certified | [LinkedIn](https://www.linkedin.com/in/pvvishnu498/)
