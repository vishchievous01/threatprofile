# ThreatProfile

**Automated Tier-1 IOC enrichment: correlates an IP across multiple threat intel sources, maps its behavior to MITRE ATT&CK, and surfaces the CVEs relevant to its exposed services — the same triage workflow a SOC analyst runs manually, encoded as a repeatable pipeline.**

## The Analyst Workflow This Replaces

When an alert fires on a suspicious source IP, a Tier-1 analyst typically has to:
1. Check reputation across AbuseIPDB and VirusTotal
2. Pull infrastructure details (ASN, org, open ports) from Shodan
3. Judge whether the observed behavior (Tor exit node, brute-force pattern, botnet C2) maps to a known MITRE ATT&CK technique
4. Cross-reference exposed services against NVD for relevant CVEs
5. Decide whether this is a known actor or a first-time sighting

This is the manual enrichment step that happens before any real investigation begins — and it's identical every time. ThreatProfile encodes that workflow into one API call.

## What It Actually Does (the security logic, not just the API calls)

- **Reputation correlation:** merges AbuseIPDB confidence scores with VirusTotal's 90+ engine detection votes into a single risk picture, rather than trusting one source
- **Technique attribution:** maps observed tags/behavior (e.g. `tor`, `botnet`, `brute-force`) to specific MITRE ATT&CK techniques (e.g. `T1090.003` – Multi-hop Proxy, `T1110` – Brute Force) — this requires knowing the ATT&CK taxonomy, not just calling an endpoint
- **Exposure-based CVE correlation:** takes the actual open ports/services detected (via Shodan InternetDB) and queries NVD for CVEs relevant to *those specific services* — e.g. an exposed Apache instance surfaces Apache CVEs, not a generic list
- **Detection rule generation:** for each identified MITRE technique, auto-generates a matching Sigma rule with the attacker's IP baked in as the indicator — turning a lookup directly into something a SIEM can ingest, rather than leaving detection engineering as a manual follow-up step
- **Persistent attacker memory:** once an IP is profiled, it's recognized instantly on future sightings instead of re-running the same lookups — mirroring how a real threat intel platform builds institutional memory over time

## Example Output

```json
{
  "ip_address": "185.220.101.1",
  "country": "DE",
  "org": "Stiftung Erneuerbare Freiheit",
  "abuse_score": 100,
  "total_reports": 164,
  "vt_malicious_votes": 13,
  "vt_suspicious_votes": 2,
  "open_ports": [80, 443, 9001, 9002],
  "hostnames": ["berlin01.tor-exit.artikel10.org"],
  "techniques": [
    {
      "technique_id": "T1090.003",
      "name": "Multi-hop Proxy",
      "tactic": "command-and-control",
      "description": "Adversaries may chain together multiple proxies to disguise the source of malicious traffic..."
    }
  ],
  "cves": [
    {
      "cve_id": "CVE-2000-1168",
      "severity": "",
      "cvss_score": 7.5,
      "description": "IBM HTTP Server 1.3.6 (based on Apache) allows remote attackers to cause a denial of service..."
    }
  ]
}
```

## Architecture

```
                    ┌──────────────────┐
   IP Address ─────▶│  Django REST API │◀───── React Frontend
                    └────────┬─────────┘        (search + profile view)
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
     AbuseIPDB          VirusTotal      Shodan (InternetDB)
   (reputation,       (detection,        (open ports,
    report count)      tags, ASN)         hostnames)
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
                    ┌──────────────────┐
                    │  Merge Engine     │
                    │  (rate-limit-safe:│
                    │  failed calls     │
                    │  never overwrite  │
                    │  good data)       │
                    └────────┬──────────┘
                    ┌────────┴──────────┐
                    ▼                   ▼
         ┌────────────────────┐  ┌──────────────────┐
         │ MITRE ATT&CK        │  │ NVD CVE Lookup    │
         │ Tag → Technique      │  │ per open port/     │
         │ Mapping              │  │ detected service    │
         └────────┬─────────────┘  └────────┬───────────┘
                    └──────────┬─────────────┘
                                ▼
                     ┌──────────────────┐
                     │  PostgreSQL/      │
                     │  SQLite DB        │
                     │  (persistent      │
                     │  attacker memory) │
                     └────────┬──────────┘
                                ▼
                     ┌──────────────────┐
                     │  REST API          │
                     │  Response (JSON)   │
                     └───────────────────┘
```

## Tech Stack

- **Backend:** Django, Django REST Framework
- **Frontend:** React (Vite), Axios
- **Database:** SQLite (dev) / PostgreSQL (production-ready)
- **Threat Intel Sources:** AbuseIPDB API, VirusTotal API, Shodan InternetDB, NVD CVE API
- **Technique Mapping:** MITRE ATT&CK Enterprise (STIX/JSON dataset)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/lookup/` | Runs full enrichment on a new IP: reputation, ports, MITRE mapping, CVE correlation |
| `GET`  | `/api/attacker/<ip>/` | Retrieves a previously-profiled attacker |
| `GET`  | `/api/attacker/<ip>/sigma/` | Generates Sigma detection rules for the attacker's identified MITRE techniques |
| `GET`  | `/api/attackers/` | Lists all profiled attackers |

### Example Request
```bash
curl -X POST http://127.0.0.1:8000/api/lookup/ \
  -H "Content-Type: application/json" \
  -d '{"ip": "185.220.101.1"}'
```

## Project Structure

```
threatprofile/
├── backend/          Django REST API, enrichment pipeline, MITRE/CVE logic
│   ├── core/          Django project settings
│   └── intel/         Models, services (API integrations), views
├── frontend/         React search UI + attacker profile card
└── README.md
```

## Setup

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file inside `backend/core/`:
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

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173`.

## Design Decisions Worth Noting

- **Rate-limit resilience:** free-tier APIs (VirusTotal especially) occasionally fail or rate-limit. The merge logic only overwrites a field if fresh data was actually returned — a failed call never wipes out a previously-good profile with zeros. This matters in any pipeline pulling from third-party APIs with quotas.
- **Rule-based technique mapping over black-box classification:** tag-to-technique mapping is explicit and auditable (a SOC tool that can't explain *why* it flagged a technique isn't trustworthy), rather than an opaque ML classifier.
- **Service-specific CVE correlation:** CVEs are pulled based on the actual detected service on each open port, not a generic "here are some CVEs" list — this is closer to how vulnerability scanners scope their results.

## Roadmap

- [x] Sigma rule generation from detected MITRE techniques
- [ ] YARA rule linkage for identified malware families
- [ ] Relationship graph (IP ↔ malware ↔ campaign ↔ CVE)
- [ ] Deployed live demo (Render/Railway)

## Why I Built This

As an EC-Council CSA-certified SOC analyst candidate, I wanted a project that demonstrates the actual judgment calls involved in IOC triage — not just API integration. The value here isn't the REST endpoints; it's encoding decisions like *which sources to trust for reputation*, *how to map observed behavior to ATT&CK techniques*, and *how to scope CVE relevance to what's actually exposed* — the same reasoning a Tier-1/Tier-2 analyst applies dozens of times a shift.

---

**Author:** Vishnu — EC-Council CSA Certified SOC Analyst [LinkedIn](https://www.linkedin.com/in/pvvishnu498/)

