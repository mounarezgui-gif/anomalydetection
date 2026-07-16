"""
icmprule.py
===========

Règles comportementales ICMP :
  - Sessions longues (échanges ICMP étalés sur une longue durée)
  - Ping Flood (rafale d'Echo Request)
  - ICMP Flood (débit ICMP global anormal, tous types confondus)
  - Taille des paquets ICMP anormale (tunneling/exfiltration via payload ICMP)
  - Nombre de requêtes ICMP élevé

Ces règles n'ont besoin d'aucun champ applicatif dédié : protocol,
length_bytes et timestamp (déjà dans le schéma d'aggregator.py) suffisent.
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

LONG_SESSION_MIN_SECONDS = 300.0
PING_FLOOD_MIN_PACKETS = 50
PING_FLOOD_WINDOW_SECONDS = 5.0
ICMP_FLOOD_MIN_PPS = 30.0
ICMP_FLOOD_MIN_PACKETS = 100
ABNORMAL_PACKET_SIZE_BYTES = 1000   # un ping standard fait ~64-84 octets
HIGH_REQUEST_COUNT_MIN = 200


def _icmp_packets(conversation: dict) -> list[dict]:
    return [p for p in conversation.get("packets", []) if p.get("protocol") == "ICMP"]


class IcmpLongSessionRule(Rule):
    """Échanges ICMP étalés sur une durée anormalement longue."""
    name = "icmp_long_session"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        if not icmp_packets:
            return []

        duration = conversation.get("duration") or 0.0
        if duration < LONG_SESSION_MIN_SECONDS:
            return []

        return [self._alert(
            conversation,
            f"Session ICMP longue : {duration / 60:.0f} min entre {conversation.get('ip_a')} "
            f"et {conversation.get('ip_b')}",
            Severity.LOW,
            evidence={"duration_seconds": duration, "packet_count": len(icmp_packets)},
        )]


class PingFloodRule(Rule):
    """Rafale de paquets ICMP (Echo Request typiquement) sur une courte fenêtre."""
    name = "icmp_ping_flood"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        if len(icmp_packets) < PING_FLOOD_MIN_PACKETS:
            return []

        timestamps = sorted(p["timestamp"] for p in icmp_packets if p.get("timestamp") is not None)
        if not timestamps:
            return []

        left = 0
        max_in_window = 1
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > PING_FLOOD_WINDOW_SECONDS:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < PING_FLOOD_MIN_PACKETS:
            return []

        severity = Severity.CRITICAL if max_in_window >= PING_FLOOD_MIN_PACKETS * 3 else Severity.HIGH
        return [self._alert(
            conversation,
            f"Ping flood suspecté : {max_in_window} paquets ICMP en moins de "
            f"{PING_FLOOD_WINDOW_SECONDS}s vers {conversation.get('ip_b')}",
            severity,
            evidence={"max_packets_in_window": max_in_window},
        )]


class IcmpFloodRule(Rule):
    """Débit ICMP global (paquets/seconde) anormalement élevé sur toute la conversation."""
    name = "icmp_flood"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        if len(icmp_packets) < ICMP_FLOOD_MIN_PACKETS:
            return []

        duration = conversation.get("duration") or 0.0
        if duration <= 0:
            return []

        pps = len(icmp_packets) / duration
        if pps < ICMP_FLOOD_MIN_PPS:
            return []

        severity = Severity.CRITICAL if pps >= ICMP_FLOOD_MIN_PPS * 4 else Severity.HIGH
        return [self._alert(
            conversation,
            f"ICMP flood suspecté : {pps:.1f} paquets/s ({len(icmp_packets)} paquets) "
            f"entre {conversation.get('ip_a')} et {conversation.get('ip_b')}",
            severity,
            evidence={"packet_count": len(icmp_packets), "pps": round(pps, 2)},
        )]


class IcmpAbnormalPacketSizeRule(Rule):
    """Paquets ICMP anormalement volumineux (payload détourné, tunneling)."""
    name = "icmp_abnormal_packet_size"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        oversized = [p for p in _icmp_packets(conversation) if p.get("length_bytes", 0) > ABNORMAL_PACKET_SIZE_BYTES]
        if not oversized:
            return []

        max_size = max(p["length_bytes"] for p in oversized)
        return [self._alert(
            conversation,
            f"Paquets ICMP anormalement volumineux : {len(oversized)} paquet(s) "
            f"> {ABNORMAL_PACKET_SIZE_BYTES} octets (max {max_size}) entre "
            f"{conversation.get('ip_a')} et {conversation.get('ip_b')}",
            Severity.MEDIUM,
            evidence={"oversized_count": len(oversized), "max_size_bytes": max_size},
        )]


class IcmpHighRequestCountRule(Rule):
    """Nombre total de requêtes/paquets ICMP élevé sur l'ensemble de la conversation."""
    name = "icmp_high_request_count"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        if len(icmp_packets) < HIGH_REQUEST_COUNT_MIN:
            return []

        return [self._alert(
            conversation,
            f"Volume de requêtes ICMP élevé : {len(icmp_packets)} paquets entre "
            f"{conversation.get('ip_a')} et {conversation.get('ip_b')}",
            Severity.MEDIUM,
            evidence={"packet_count": len(icmp_packets)},
        )]


RULES = [
    IcmpLongSessionRule(),
    PingFloodRule(),
    IcmpFloodRule(),
    IcmpAbnormalPacketSizeRule(),
    IcmpHighRequestCountRule(),
]