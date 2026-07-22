"""
icmprule.py
===========

Règles comportementales ICMP :
  - Sessions longues (échanges ICMP étalés sur une longue durée)
  - Ping Flood (rafale d'Echo Request)
  - ICMP Flood (débit ICMP global anormal, tous types confondus)
  - Taille des paquets ICMP anormale (tunneling/exfiltration via payload ICMP)
  - Nombre de requêtes ICMP élevé

L'attaquant et la cible sont déterminés à partir des champs src_ip/dst_ip
des paquets eux-mêmes, jamais depuis ip_a/ip_b de la conversation : ces
derniers n'ont pas de sens directionnel garanti (assignés arbitrairement
par aggregator.py), et les utiliser directement peut inverser attaquant
et victime dans le message d'alerte.
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


def _identify_attacker_and_target(icmp_packets: list[dict]) -> tuple[str | None, str | None]:
    """
    Détermine l'attaquant (source majoritaire des paquets) et la cible
    (destination majoritaire), en comptant les src_ip/dst_ip réels des
    paquets ICMP de la conversation.
    """
    dst_counts: dict[str, int] = {}
    src_counts: dict[str, int] = {}
    for p in icmp_packets:
        if p.get("dst_ip"):
            dst_counts[p["dst_ip"]] = dst_counts.get(p["dst_ip"], 0) + 1
        if p.get("src_ip"):
            src_counts[p["src_ip"]] = src_counts.get(p["src_ip"], 0) + 1

    target = max(dst_counts, key=dst_counts.get) if dst_counts else None
    attacker = max(src_counts, key=src_counts.get) if src_counts else None
    return attacker, target


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

        attacker, target = _identify_attacker_and_target(icmp_packets)
        return [self._alert(
            conversation,
            f"Session ICMP longue : {duration / 60:.0f} min entre {attacker} et {target}",
            Severity.LOW,
            evidence={"duration_seconds": duration, "packet_count": len(icmp_packets)},
            cible=target,
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

        attacker, target = _identify_attacker_and_target(icmp_packets)
        severity = Severity.CRITICAL if max_in_window >= PING_FLOOD_MIN_PACKETS * 3 else Severity.HIGH
        return [self._alert(
            conversation,
            f"Ping flood suspecté : {max_in_window} paquets ICMP en moins de "
            f"{PING_FLOOD_WINDOW_SECONDS}s de {attacker} vers {target}",
            severity,
            evidence={"max_packets_in_window": max_in_window, "attacker": attacker, "target": target},
            cible=target,
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

        attacker, target = _identify_attacker_and_target(icmp_packets)
        severity = Severity.CRITICAL if pps >= ICMP_FLOOD_MIN_PPS * 4 else Severity.HIGH
        return [self._alert(
            conversation,
            f"ICMP flood suspecté : {pps:.1f} paquets/s ({len(icmp_packets)} paquets) "
            f"de {attacker} vers {target}",
            severity,
            evidence={"packet_count": len(icmp_packets), "pps": round(pps, 2), "attacker": attacker, "target": target},
            cible=target,
        )]


class IcmpAbnormalPacketSizeRule(Rule):
    """Paquets ICMP anormalement volumineux (payload détourné, tunneling)."""
    name = "icmp_abnormal_packet_size"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        oversized = [p for p in icmp_packets if p.get("length_bytes", 0) > ABNORMAL_PACKET_SIZE_BYTES]
        if not oversized:
            return []

        max_size = max(p["length_bytes"] for p in oversized)
        attacker, target = _identify_attacker_and_target(oversized)
        return [self._alert(
            conversation,
            f"Paquets ICMP anormalement volumineux : {len(oversized)} paquet(s) "
            f"> {ABNORMAL_PACKET_SIZE_BYTES} octets (max {max_size}) de {attacker} vers {target}",
            Severity.MEDIUM,
            evidence={"oversized_count": len(oversized), "max_size_bytes": max_size},
            cible=target,
        )]


class IcmpHighRequestCountRule(Rule):
    """Nombre total de requêtes/paquets ICMP élevé sur l'ensemble de la conversation."""
    name = "icmp_high_request_count"
    protocol = "ICMP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        icmp_packets = _icmp_packets(conversation)
        if len(icmp_packets) < HIGH_REQUEST_COUNT_MIN:
            return []

        attacker, target = _identify_attacker_and_target(icmp_packets)
        return [self._alert(
            conversation,
            f"Volume de requêtes ICMP élevé : {len(icmp_packets)} paquets de {attacker} vers {target}",
            Severity.MEDIUM,
            evidence={"packet_count": len(icmp_packets)},
            cible=target,
        )]


RULES = [
    IcmpLongSessionRule(),
    PingFloodRule(),
    IcmpFloodRule(),
    IcmpAbnormalPacketSizeRule(),
    IcmpHighRequestCountRule(),
]