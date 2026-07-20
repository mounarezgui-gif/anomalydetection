"""
dhcprule.py
===========

Règles comportementales DHCP :
  - DhcpStarvationRule : beaucoup de DISCOVER envoyés par des MAC
    distinctes en peu de temps -> tentative d'épuisement du pool
    d'adresses IP du serveur DHCP légitime.

Nécessite les champs "dhcp_message_type" et "client_mac" ajoutés dans
extractor.py (voir DHCP_MESSAGE_TYPES / eth.src) et propagés par
aggregator.py::_format_packet.

LIMITATION : la détection de serveur DHCP rogue (une IP non autorisée
qui répond avec des OFFER) nécessite de comparer plusieurs conversations
entre elles (plusieurs IPs serveur répondant au même client), ce que
l'interface Rule.evaluate(conversation) ne permet pas (une seule
conversation à la fois). Elle n'est donc pas implémentée ici -> il
faudrait une règle "globale" opérant sur toutes les conversations,
architecture différente de celle utilisée par vos autres fichiers.
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

DHCP_STARVATION_MIN_DISCOVERS = 20     # DISCOVER distincts (par MAC) minimum
DHCP_STARVATION_WINDOW_SECONDS = 30.0  # concentrés dans cette fenêtre


class DhcpStarvationRule(Rule):
    """
    Beaucoup de requêtes DHCPDISCOVER émises par des adresses MAC
    différentes, concentrées dans une fenêtre de temps courte ->
    starvation suspectée (épuisement volontaire du pool DHCP).
    """
    name = "dhcp_starvation"
    protocol = "DHCP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if "DHCP" not in conversation.get("protocols_used", []):
            return []

        discovers = [
            p for p in conversation.get("packets", [])
            if p.get("protocol") == "DHCP" and p.get("dhcp_message_type") == "DISCOVER"
        ]

        # On ne compte qu'une seule fois par MAC distincte : un client
        # légitime qui retransmet son DISCOVER (perte de paquet) ne doit
        # pas gonfler artificiellement le compte.
        first_seen_per_mac: dict[str, float] = {}
        for p in discovers:
            mac = p.get("client_mac")
            ts = p.get("timestamp")
            if mac is None or ts is None:
                continue
            if mac not in first_seen_per_mac:
                first_seen_per_mac[mac] = ts

        distinct_macs = len(first_seen_per_mac)
        if distinct_macs < DHCP_STARVATION_MIN_DISCOVERS:
            return []

        # Fenêtre glissante sur les horodatages de première apparition
        # de chaque MAC (même technique que SshBruteforceRule)./(sliding window)
        timestamps = sorted(first_seen_per_mac.values())
        left = 0
        max_in_window = 1
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > DHCP_STARVATION_WINDOW_SECONDS:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < DHCP_STARVATION_MIN_DISCOVERS:
            return []

        return [self._alert(
            conversation,
            f"DHCP starvation suspectée : {max_in_window} clients distincts (MAC) "
            f"ont envoyé un DISCOVER en moins de {DHCP_STARVATION_WINDOW_SECONDS:.0f}s "
            f"vers {conversation.get('ip_b')}",
            Severity.CRITICAL,
            evidence={
                "distinct_macs_in_window": max_in_window,
                "total_distinct_macs": distinct_macs,
                "window_seconds": DHCP_STARVATION_WINDOW_SECONDS,
            },
        )]


RULES = [DhcpStarvationRule()]