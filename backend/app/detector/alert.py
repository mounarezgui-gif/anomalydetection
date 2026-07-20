"""
alert.py
========

Format d'alerte standard, partagé par TOUTES les règles du moteur
(réputation, TCP, UDP, ICMP, HTTP, DNS, TLS, FTP, comportemental).

Chaque règle doit retourner soit None (rien à signaler), soit le résultat
de make_alert(). Ça garantit que toutes les alertes, quelle que soit la
règle qui les a générées, ont exactement la même forme et peuvent être
stockées/affichées ensemble.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


# Sévérités valides, du moins grave au plus grave.
SEVERITY_LEVELS = ["INFO", "WARNING", "SUSPICIOUS", "CRITICAL"]


def make_alert(
    rule_id: str,
    protocole: str,
    cible: str,
    severite: str,
    description: str,
    details: Optional[dict] = None,
    conversation_id: Optional[int] = None,
    packet_number: Optional[int] = None,
) -> dict:
    """
    Construit une alerte au format standard.

    Args:
        rule_id: identifiant unique de la règle (ex: "TCP_01_PORT_NON_AUTORISE")
        protocole: "TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS", "FTP", "DNS/REPUTATION"...
        cible: IP, couple IP:port, ou domaine concerné
        severite: un des SEVERITY_LEVELS
        description: message humain expliquant l'alerte
        details: dictionnaire libre avec les infos brutes utiles (flags, ports, tailles...)
        conversation_id: id de la conversation source (si applicable)
        packet_number: numéro du paquet source (si l'alerte vient d'un paquet précis)
    """
    if severite not in SEVERITY_LEVELS:
        raise ValueError(f"Sévérité invalide: {severite}. Attendu: {SEVERITY_LEVELS}")

    return {
        "rule_id": rule_id,
        "protocole": protocole,
        "cible": cible,
        "severite": severite,
        "description": description,
        "details": details or {},
        "conversation_id": conversation_id,
        "packet_number": packet_number,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }