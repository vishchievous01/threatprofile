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

SIGMA_TEMPLATES = {
    'T1090.003': """title: Traffic to Known Tor Exit Node
id: {rule_id}
status: experimental
description: Detects outbound or inbound traffic involving a known Tor exit node IP, indicating potential anonymized C2 or exfiltration.
references:
    - https://attack.mitre.org/techniques/T1090/003/
tags:
    - attack.command_and_control
    - attack.t1090.003
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '{ip}'
    condition: selection
falsepositives:
    - Legitimate Tor usage (privacy tools, journalists, researchers)
level: medium
""",
    'T1110': """title: Possible Brute Force Activity from Known Bad IP
id: {rule_id}
status: experimental
description: Detects authentication attempts originating from an IP with a history of brute-force behavior.
references:
    - https://attack.mitre.org/techniques/T1110/
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: security
    definition: 'Requires Event ID 4625 (failed logon) auditing enabled'
detection:
    selection:
        EventID: 4625
        IpAddress: '{ip}'
    timeframe: 5m
    condition: selection | count() by IpAddress > 5
falsepositives:
    - Misconfigured service accounts
    - Legitimate user password mistakes
level: high
""",
    'T1021.004': """title: SSH Connection from Known Malicious IP
id: {rule_id}
status: experimental
description: Detects SSH connection attempts from an IP flagged for malicious remote service abuse.
references:
    - https://attack.mitre.org/techniques/T1021/004/
tags:
    - attack.lateral_movement
    - attack.t1021.004
logsource:
    category: firewall
detection:
    selection:
        dst_port: 22
        src_ip: '{ip}'
    condition: selection
falsepositives:
    - Authorized remote administration
level: medium
""",
    'T1566': """title: Inbound Traffic from IP Associated with Phishing Infrastructure
id: {rule_id}
status: experimental
description: Detects network traffic from an IP previously associated with phishing campaigns.
references:
    - https://attack.mitre.org/techniques/T1566/
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    category: proxy
detection:
    selection:
        c-ip: '{ip}'
    condition: selection
falsepositives:
    - Shared hosting infrastructure with mixed reputation
level: medium
""",
    'T1587.001': """title: Traffic from IP Linked to Known Malware Infrastructure
id: {rule_id}
status: experimental
description: Detects traffic involving an IP associated with malware development/hosting infrastructure.
references:
    - https://attack.mitre.org/techniques/T1587/001/
tags:
    - attack.resource_development
    - attack.t1587.001
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '{ip}'
    condition: selection
falsepositives:
    - IP reassignment after infrastructure cleanup
level: high
""",
    'T1584.005': """title: Traffic from IP Associated with Known Botnet Infrastructure
id: {rule_id}
status: experimental
description: Detects communication with an IP identified as part of a botnet's compromised infrastructure.
references:
    - https://attack.mitre.org/techniques/T1584/005/
tags:
    - attack.resource_development
    - attack.t1584.005
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '{ip}'
    condition: selection
falsepositives:
    - IP reassignment after takedown
level: high
""",
    'T1595': """title: Active Scanning Activity from Known Scanner IP
id: {rule_id}
status: experimental
description: Detects inbound reconnaissance/scanning traffic from an IP known for active scanning behavior.
references:
    - https://attack.mitre.org/techniques/T1595/
tags:
    - attack.reconnaissance
    - attack.t1595
logsource:
    category: firewall
detection:
    selection:
        src_ip: '{ip}'
        connection_state: 'SYN'
    timeframe: 1m
    condition: selection | count() by src_ip > 20
falsepositives:
    - Legitimate vulnerability scanning by internal security teams
level: low
""",
}


def generate_sigma_rule(technique_id, ip):
    template = SIGMA_TEMPLATES.get(technique_id)
    if not template:
        return None
    import uuid
    rule_id = str(uuid.uuid4())
    return template.format(ip=ip, rule_id=rule_id)

def map_tags_to_techniques(tags):
    technique_ids = set()
    for tag in tags:
        tag_lower = tag.lower()
        for key, ids in TAG_TECHNIQUE_MAP.items():
            if key in tag_lower:
                technique_ids.update(ids)
    return list(technique_ids)

PORT_SERVICE_MAP = {
    21: 'FTP',
    22: 'OpenSSH',
    23: 'Telnet',
    25: 'SMTP',
    80: 'Apache HTTP Server',
    443: 'SSL',
    3306: 'MySQL',
    3389: 'RDP',
    8080: 'Apache Tomcat',
}

def get_cves_for_ports(ports):
    all_cves = []
    seen_ids = set()
    for port in ports:
        service = PORT_SERVICE_MAP.get(port)
        if not service:
            continue
        result = search_cve(service)
        vulns = result.get('vulnerabilities', [])[:3]  # top 3 per service
        for v in vulns:
            cve_data = v.get('cve', {})
            cve_id = cve_data.get('id')
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                descriptions = cve_data.get('descriptions', [])
                desc_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                severity = ''
                if 'cvssMetricV31' in metrics:
                    cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV2' in metrics:
                    cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                all_cves.append({
                    'cve_id': cve_id,
                    'description': desc_text[:500],
                    'severity': severity,
                    'cvss_score': cvss_score,
                })
    return all_cves

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
    if resp.status_code != 200:
        print(f"VirusTotal error {resp.status_code}: {resp.text}")
        return {}
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
    vt_response = check_virustotal(ip)
    vt = vt_response.get('data', {}).get('attributes', {})
    shodan = check_shodan(ip)

    vt_stats = vt.get('last_analysis_stats', {})
    ports = shodan.get('ports', [])
    cves = get_cves_for_ports(ports) if ports else []

    profile = {
        'country': abuse.get('countryCode', ''),
        'isp': abuse.get('isp', ''),
        'abuse_score': abuse.get('abuseConfidenceScore', 0),
        'total_reports': abuse.get('totalReports', 0),
        'raw_data': {
            'abuseipdb': abuse,
            'virustotal': vt,
            'shodan': shodan,
        },
        '_cves': cves,
    }

    # Only overwrite VT/Shodan fields if we actually got fresh data,
    # so a rate-limited or failed call doesn't wipe out good existing data.
    if vt:
        profile['vt_malicious_votes'] = vt_stats.get('malicious', 0)
        profile['vt_suspicious_votes'] = vt_stats.get('suspicious', 0)
        profile['vt_reputation'] = vt.get('reputation', 0)
        profile['org'] = vt.get('as_owner', '')

    if shodan:
        profile['open_ports'] = ports
        profile['hostnames'] = shodan.get('hostnames', [])

    return profile

def search_cve(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': keyword, 'resultsPerPage': 5}
    resp = requests.get(url, params=params)
    if resp.status_code == 200:
        return resp.json()
    return {}