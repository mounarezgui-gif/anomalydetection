"""
portrule.py
===========

Règle comportementale : un protocole applicatif identifié (HTTP, HTTPS,
DNS, DHCP, SSH, FTP) tourne sur un port différent de son port standard.

S'appuie directement sur le champ "default_port" déjà calculé par
extractor.py (_is_default_port) pour chaque paquet -> aucune table de
ports dupliquée ici, pas de risque de désynchronisation avec extractor.py.

Les protocoles sans port standard connu (TCP/UDP génériques, ICMP...)
ne sont jamais concernés : leur "protocol" n'a pas d'entrée dans
extractor.DEFAULT_PORTS, donc default_port vaut toujours False pour eux
et ne doit pas déclencher d'alerte.
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

# Doit rester synchronisé avec extractor.DEFAULT_PORTS : uniquement les
# noms de protocoles pour lesquels un port standard existe et pour
# lesquels une alerte a du sens si default_port est False.
PROTOCOLS_WITH_STANDARD_PORT = {"HTTP", "HTTPS", "DNS", "DHCP", "SSH", "FTP"}


class PortProtocolMismatchRule(Rule):
    """
    Un paquet dont le protocole applicatif est identifié mais dont
    default_port vaut False -> le protocole tourne sur un port non
    standard (tunneling, évasion, service mal configuré).
    """
    name = "port_protocol_mismatch"
    protocol = "MULTI"

    def evaluate(self, conversation: dict) -> list[Alert]:
        alerts: list[Alert] = []
        seen: set[tuple] = set()  # évite les doublons (protocole, ports) répétés

        for p in conversation.get("packets", []):
            proto = p.get("protocol")
            if proto not in PROTOCOLS_WITH_STANDARD_PORT:
                continue

            if p.get("default_port"):
                continue  # port standard respecté, rien à signaler

            sport = p.get("src_port")
            dport = p.get("dst_port")
            if sport is None or dport is None:
                continue

            key = (proto, sport, dport)
            if key in seen:
                continue
            seen.add(key)

            alerts.append(self._alert(
                conversation,
                f"{proto} détecté sur port non standard : "
                f"{conversation.get('ip_a')}:{sport} -> {conversation.get('ip_b')}:{dport}",
                Severity.MEDIUM,
                evidence={
                    "detected_protocol": proto,
                    "src_port": sport,
                    "dst_port": dport,
                },
                cible=f"{conversation.get('ip_b')}:{dport}",
                packet_number=p.get("packet_number"),
            ))

        return alerts


RULES = [PortProtocolMismatchRule()]