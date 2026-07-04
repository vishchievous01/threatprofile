from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Attacker
from .serializers import AttackerSerializer
from .services import build_profile, load_mitre_techniques, map_tags_to_techniques
from .models import MitreTechnique

@api_view(['GET'])
def get_attacker(request, ip):
    try:
        attacker = Attacker.objects.get(ip_address=ip)
        serializer = AttackerSerializer(attacker)
        return Response(serializer.data)
    except Attacker.DoesNotExist:
        return Response({'error': 'Not found. Run a lookup first.'}, status=404)

@api_view(['POST'])
def lookup_and_profile(request):
    ip = request.data.get('ip')
    if not ip:
        return Response({'error': 'ip is required'}, status=400)

    profile = build_profile(ip)
    attacker, _ = Attacker.objects.update_or_create(ip_address=ip, defaults=profile)

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

    serializer = AttackerSerializer(attacker)
    return Response(serializer.data)

@api_view(['GET'])
def list_attackers(request):
    attackers = Attacker.objects.all().order_by('-last_checked')
    serializer = AttackerSerializer(attackers, many=True)
    return Response(serializer.data)