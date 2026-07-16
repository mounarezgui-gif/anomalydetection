"""
tcprule.py
==========

Règles comportementales TCP :
  - Handshake incomplet (SYN sans SYN/ACK+ACK, à l'échelle du tcp.stream)
  - SYN Flood (beaucoup de SYN isolés vers un même hôte, débit élevé)

S'appuie sur le champ `packet["tcp"]["handshake"]` déjà calculé par
aggregator.py (_compute_tcp_handshakes / _attach_handshakes).
"""

from __future__ import annotations

from collections import defaultdict

from .common import Rule, Severity, Alert

# Seuils (à ajuster selon le contexte du réseau capturé)
SYN_FLOOD_MIN_SYN = 2          # nombre de SYN "orphelins" minimum
SYN_FLOOD_MAX_WINDOW_SECONDS = 5.0  # fenêtre de temps considérée comme "rafale"
INCOMPLETE_HANDSHAKE_MIN_RATIO = 0.5  # part de streams incomplets jugée anormale


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
        for packet in conversation.get("packets", []):
            tcp = packet.get("tcp")
            if not tcp or tcp.get("stream") is None:
                continue
            streams[tcp["stream"]] = tcp.get("handshake", {})

        if not streams:
            return []

        incomplete = [sid for sid, hs in streams.items() if not hs.get("completed", False)]
        if not incomplete:
            return []

        ratio = len(incomplete) / len(streams)
        if ratio < INCOMPLETE_HANDSHAKE_MIN_RATIO:
            return []

        severity = Severity.HIGH if ratio >= 0.8 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"{len(incomplete)}/{len(streams)} handshake(s) TCP incomplet(s) "
            f"({ratio:.0%}) entre {conversation.get('ip_a')} et {conversation.get('ip_b')}",
            severity,
            evidence={
                "incomplete_streams": incomplete,
                "total_streams": len(streams),
                "ratio": round(ratio, 2),
            },
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

        syn_times: list[float] = []
        for packet in conversation.get("packets", []):
            tcp = packet.get("tcp")
            if not tcp:
                continue
            if tcp.get("syn") and not tcp.get("ack"):
                ts = packet.get("timestamp")
                if ts is not None:
                    syn_times.append(ts)

        if len(syn_times) < SYN_FLOOD_MIN_SYN:
            return []

        syn_times.sort()
        # Fenêtre glissante : le plus grand nombre de SYN tombant dans une
        # fenêtre <= SYN_FLOOD_MAX_WINDOW_SECONDS.
        left = 0
        max_in_window = 1
        for right in range(len(syn_times)):
            while syn_times[right] - syn_times[left] > SYN_FLOOD_MAX_WINDOW_SECONDS:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < SYN_FLOOD_MIN_SYN:
            return []

        severity = Severity.CRITICAL if max_in_window >= SYN_FLOOD_MIN_SYN * 3 else Severity.HIGH
        return [self._alert(
            conversation,
            f"SYN flood suspecté : {max_in_window} paquets SYN en moins de "
            f"{SYN_FLOOD_MAX_WINDOW_SECONDS}s vers {conversation.get('ip_b')}",
            severity,
            evidence={"max_syn_in_window": max_in_window, "total_syn": len(syn_times)},
        )]


RULES = [IncompleteHandshakeRule(), SynFloodRule()]