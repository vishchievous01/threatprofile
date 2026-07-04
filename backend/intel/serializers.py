from rest_framework import serializers
from .models import Attacker, MitreTechnique, CVE

class MitreTechniqueSerializer(serializers.ModelSerializer):
    class Meta:
        model = MitreTechnique
        fields = ['technique_id', 'name', 'tactic', 'description']

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = ['cve_id', 'description', 'severity', 'cvss_score']

class AttackerSerializer(serializers.ModelSerializer):
    techniques = MitreTechniqueSerializer(many=True, read_only=True)
    cves = CVESerializer(many=True, read_only=True)

    class Meta:
        model = Attacker
        fields = [
            'ip_address', 'country', 'isp', 'org', 'abuse_score',
            'total_reports', 'vt_malicious_votes', 'vt_suspicious_votes',
            'vt_reputation', 'open_ports', 'hostnames', 'first_seen',
            'last_checked', 'techniques', 'cves'
        ]