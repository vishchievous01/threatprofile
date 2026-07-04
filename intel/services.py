import requests
from django.conf import settings

import json

def load_mitre_techniques():
    with open('intel/mitre_data.json', encoding='utf-8') as f:
        data = json.load(f)
    techniques = {}
    for obj in data['objects']:
        if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
            ext_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    ext_id = ref.get('external_id')
                    break
            if ext_id:
                techniques[ext_id] = {
                    'id': ext_id,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', '')[:500],
                    'tactic': ', '.join(
                        [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
                    )
                }
    return techniques

TAG_TECHNIQUE_MAP = {
    'tor': ['T1090.003'],
    'brute-force': ['T1110'],
    'ssh': ['T1021.004'],
    'phishing': ['T1566'],
    'malware': ['T1587.001'],
    'botnet': ['T1584.005'],
    'scanner': ['T1595'],
}

def map_tags_to_techniques(tags):
    technique_ids = set()
    for tag in tags:
        tag_lower = tag.lower()
        for key, ids in TAG_TECHNIQUE_MAP.items():
            if key in tag_lower:
                technique_ids.update(ids)
    return list(technique_ids)

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers= {'key': settings.ABUSEIPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    resp = requests.get(url, headers=headers, params=params)
    return resp.json()

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': settings.VT_KEY}
    resp = requests.get(url, headers=headers)
    return resp.json()

def check_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {'key': settings.SHODAN_KEY}
    resp = requests.get(url, params=params)
    if resp.status_code == 200:
        return resp.json()
    return {}

def build_profile(ip):
    abuse = check_abuseipdb(ip).get('data', {})
    vt = check_virustotal(ip).get('data', {}).get('attributes', {})
    shodan = check_shodan(ip)

    vt_stats = vt.get('last_analysis_stats', {})

    return {
        'country': abuse.get('countryCode', ''),
        'isp': abuse.get('isp', ''),
        'abuse_score': abuse.get('abuseConfidenceScore', 0),
        'total_reports': abuse.get('totalReports', 0),
        'vt_malicious_votes': vt_stats.get('malicious', 0),
        'vt_suspicious_votes': vt_stats.get('suspicious', 0),
        'vt_reputation': vt.get('reputation', 0),
        'open_ports': shodan.get('ports', []),
        'org': vt.get('as_owner', ''),
        'hostnames': shodan.get('hostnames', []),
        'raw_data': {
            'abuseipdb': abuse,
            'virustotal': vt,
            'shodan': shodan,
        }
    }

def search_cve(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': keyword, 'resultsPerPage': 5}
    resp = requests.get(url, params=params)
    if resp.status_code == 200:
        return resp.json()
    return {}