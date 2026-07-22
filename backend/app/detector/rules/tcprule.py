"""
tcprule.py
==========

Règles comportementales TCP :
  - Handshake incomplet (SYN sans SYN/ACK+ACK, à l'échelle du tcp.stream)
  - SYN Flood (beaucoup de SYN isolés vers un même hôte, débit élevé)

S'appuie sur le champ `packet["tcp"]["handshake"]` déjà calculé par
aggregator.py (_compute_tcp_handshakes / _attach_handshakes).

La cible est déterminée à partir des dst_ip réels des paquets SYN,
jamais depuis ip_a/ip_b de la conversation (sans direction garantie).
"""

from __future__ import annotations

from collections import defaultdict

from .common import Rule, Severity, Alert

SYN_FLOOD_MIN_SYN = 20
SYN_FLOOD_MAX_WINDOW_SECONDS = 5.0
INCOMPLETE_HANDSHAKE_MIN_RATIO = 0.5


def _identify_initiator_and_target(syn_packets: list[dict]) -> tuple[str | None, str | None]:
    """
    Pour des paquets SYN (sans ACK), la source est celui qui initie la
    connexion, la destination est la cible visée.
    """
    src_counts: dict[str, int] = {}
    dst_counts: dict[str, int] = {}
    for p in syn_packets:
        if p.get("src_ip"):
            src_counts[p["src_ip"]] = src_counts.get(p["src_ip"], 0) + 1
        if p.get("dst_ip"):
            dst_counts[p["dst_ip"]] = dst_counts.get(p["dst_ip"], 0) + 1

    initiator = max(src_counts, key=src_counts.get) if src_counts else None
    target = max(dst_counts, key=dst_counts.get) if dst_counts else None
    return initiator, target


class IncompleteHandshakeRule(Rule):
    """
    Détecte les tcp.stream qui n'ont jamais atteint l'état "completed"
    (SYN -> SYN/ACK -> ACK) au sein de la conversation.
    """
    name = "tcp_incomplete_handshake"
    protocol = "TCP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if "TCP" not in conversation.get("protocols_used", []):
            return []

        streams: dict[int, dict] = {}
        syn_packets_by_stream: dict[int, dict] = {}
        for packet in conversation.get("packets", []):
            tcp = packet.get("tcp")
            if not tcp or tcp.get("stream") is None:
                continue
            streams[tcp["stream"]] = tcp.get("handshake", {})
            if tcp.get("syn") and not tcp.get("ack") and tcp["stream"] not in syn_packets_by_stream:
                syn_packets_by_stream[tcp["stream"]] = packet

        if not streams:
            return []

        incomplete = [sid for sid, hs in streams.items() if not hs.get("completed", False)]
        if not incomplete:
            return []

        ratio = len(incomplete) / len(streams)
        if ratio < INCOMPLETE_HANDSHAKE_MIN_RATIO:
            return []

        incomplete_syns = [syn_packets_by_stream[sid] for sid in incomplete if sid in syn_packets_by_stream]
        initiator, target = _identify_initiator_and_target(incomplete_syns)

        severity = Severity.HIGH if ratio >= 0.8 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"{len(incomplete)}/{len(streams)} handshake(s) TCP incomplet(s) "
            f"({ratio:.0%}) entre {initiator} et {target}",
            severity,
            evidence={
                "incomplete_streams": incomplete,
                "total_streams": len(streams),
                "ratio": round(ratio, 2),
            },
            cible=target,
        )]


class SynFloodRule(Rule):
    """
    Détecte une rafale de paquets SYN (sans ACK, jamais suivis d'un
    SYN/ACK complet côté même stream) concentrée sur une courte fenêtre
    de temps -> signature de SYN flood.
    """
    name = "tcp_syn_flood"
    protocol = "TCP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if "TCP" not in conversation.get("protocols_used", []):
            return []

        syn_packets: list[dict] = []
        for packet in conversation.get("packets", []):
            tcp = packet.get("tcp")
            if not tcp:
                continue
            if tcp.get("syn") and not tcp.get("ack") and packet.get("timestamp") is not None:
                syn_packets.append(packet)

        if len(syn_packets) < SYN_FLOOD_MIN_SYN:
            return []

        syn_packets.sort(key=lambda p: p["timestamp"])
        syn_times = [p["timestamp"] for p in syn_packets]

        left = 0
        max_in_window = 1
        window_end_idx = 0
        for right in range(len(syn_times)):
            while syn_times[right] - syn_times[left] > SYN_FLOOD_MAX_WINDOW_SECONDS:
                left += 1
            if right - left + 1 > max_in_window:
                max_in_window = right - left + 1
                window_end_idx = right

        if max_in_window < SYN_FLOOD_MIN_SYN:
            return []

        # Recalcule la fenêtre effective retenue pour identifier initiateur/cible
        window_start_idx = window_end_idx - max_in_window + 1
        window_packets = syn_packets[window_start_idx:window_end_idx + 1]
        initiator, target = _identify_initiator_and_target(window_packets)

        severity = Severity.CRITICAL if max_in_window >= SYN_FLOOD_MIN_SYN * 3 else Severity.HIGH
        return [self._alert(
            conversation,
            f"SYN flood suspecté : {max_in_window} paquets SYN en moins de "
            f"{SYN_FLOOD_MAX_WINDOW_SECONDS}s depuis {initiator} vers {target}",
            severity,
            evidence={"max_syn_in_window": max_in_window, "total_syn": len(syn_times)},
            cible=target,
        )]


RULES = [IncompleteHandshakeRule(), SynFloodRule()]