from django.db import models

class Attacker(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    country = models.CharField(max_length=100, blank=True)
    isp = models.CharField(max_length=200, blank=True)
    abuse_score = models.IntegerField(default=0)
    total_reports = models.IntegerField(default=0)

    vt_malicious_votes = models.IntegerField(default=0)
    vt_suspicious_votes = models.IntegerField(default=0)
    vt_reputation = models.IntegerField(default=0)

    open_ports = models.JSONField(default=list)
    org = models.CharField(max_length=200, blank=True)
    hostnames = models.JSONField(default=list)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_checked = models.DateTimeField(auto_now=True)
    raw_data = models.JSONField(default=dict)

    def __str__(self):
        return self.ip_address

class CVE(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, blank=True)
    cvss_score = models.FloatField(default=0.0)
    attackers = models.ManyToManyField(Attacker, related_name='cves')

    def __str__(self):
        return self.cve_id

class MitreTechnique(models.Model):
    technique_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=200)
    tactic = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    attackers = models.ManyToManyField(Attacker, related_name='techniques')

    def __str__(self):
        return f"{self.technique_id} - {self.name}"