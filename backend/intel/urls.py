from django.urls import path
from . import views

urlpatterns = [
    path('attacker/<str:ip>/', views.get_attacker, name='get_attacker'),
    path('attacker/<str:ip>/sigma/', views.get_sigma_rules, name='get_sigma_rules'),
    path('lookup/', views.lookup_and_profile, name='lookup_and_profile'),
    path('attackers/', views.list_attackers, name='list_attackers'),
]