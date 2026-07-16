"""
udprule.py
==========

Règles comportementales UDP :
  - UDP Flood (débit de paquets UDP anormalement élevé entre deux hôtes)
  - UDP Scan (un hôte sonde un grand nombre de ports UDP distincts)
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

UDP_FLOOD_MIN_PACKETS = 100
UDP_FLOOD_MIN_PPS = 50.0          # paquets/seconde
UDP_SCAN_MIN_DISTINCT_PORTS = 15  # ports distincts sondés côté destination


class UdpFloodRule(Rule):
    """Débit UDP (paquets/seconde) anormalement élevé sur la conversation."""
    name = "udp_flood"
    protocol = "UDP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if "UDP" not in conversation.get("protocols_used", []):
            return []

        udp_packets = [p for p in conversation.get("packets", []) if p.get("protocol") == "UDP"]
        if len(udp_packets) < UDP_FLOOD_MIN_PACKETS:
            return []

        duration = conversation.get("duration") or 0.0
        if duration <= 0:
            return []

        pps = len(udp_packets) / duration
        if pps < UDP_FLOOD_MIN_PPS:
            return []

        severity = Severity.CRITICAL if pps >= UDP_FLOOD_MIN_PPS * 4 else Severity.HIGH
        return [self._alert(
            conversation,
            f"UDP flood suspecté : {pps:.1f} paquets/s ({len(udp_packets)} paquets "
            f"sur {duration:.2f}s) entre {conversation.get('ip_a')} et {conversation.get('ip_b')}",
            severity,
            evidence={"packet_count": len(udp_packets), "duration": duration, "pps": round(pps, 2)},
        )]


class UdpScanRule(Rule):
    """
    Un même hôte source contacte un grand nombre de ports UDP distincts
    sur le même hôte destination -> balayage de ports (scan).
    """
    name = "udp_scan"
    protocol = "UDP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if "UDP" not in conversation.get("protocols_used", []):
            return []

        # Ports destination distincts touchés par des paquets UDP
        dst_ports: set[int] = set()
        for p in conversation.get("packets", []):
            if p.get("protocol") == "UDP" and p.get("dst_port") is not None:
                dst_ports.add(p["dst_port"])

        if len(dst_ports) < UDP_SCAN_MIN_DISTINCT_PORTS:
            return []

        severity = Severity.HIGH if len(dst_ports) >= UDP_SCAN_MIN_DISTINCT_PORTS * 2 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"UDP scan suspecté : {len(dst_ports)} ports UDP distincts sondés "
            f"vers {conversation.get('ip_b')}",
            severity,
            evidence={"distinct_ports": sorted(dst_ports)[:50], "count": len(dst_ports)},
        )]


RULES = [UdpFloodRule(), UdpScanRule()]