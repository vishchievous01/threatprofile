from django.core.management.base import BaseCommand
from intel.services import build_profile, load_mitre_techniques, map_tags_to_techniques
from intel.models import Attacker, MitreTechnique, CVE

class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('ip', type=str)

    def handle(self, *args, **options):
        ip = options['ip']
        profile = build_profile(ip)
        cves = profile.pop('_cves', [])

        attacker, created = Attacker.objects.update_or_create(
            ip_address=ip,
            defaults=profile
        )

        vt_tags = profile['raw_data']['virustotal'].get('tags', [])
        technique_ids = map_tags_to_techniques(vt_tags)

        if technique_ids:
            all_techniques = load_mitre_techniques()
            for tid in technique_ids:
                info = all_techniques.get(tid)
                if info:
                    mitre_obj, _ = MitreTechnique.objects.update_or_create(
                        technique_id=tid,
                        defaults={'name': info['name'], 'tactic': info['tactic'], 'description': info['description']}
                    )
                    mitre_obj.attackers.add(attacker)

        for cve_data in cves:
            cve_obj, _ = CVE.objects.update_or_create(
                cve_id=cve_data['cve_id'],
                defaults={
                    'description': cve_data['description'],
                    'severity': cve_data['severity'],
                    'cvss_score': cve_data['cvss_score'],
                }
            )
            cve_obj.attackers.add(attacker)

        status = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(
            f"{status}: {ip} | Abuse: {attacker.abuse_score}% | "
            f"MITRE: {technique_ids} | CVEs: {len(cves)}"
        ))