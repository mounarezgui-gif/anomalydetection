"""
httpsrule.py
============

Règles comportementales HTTPS/TLS :
  - Handshake TLS échoué (alert/reset avant ApplicationData)
  - Sessions longues
  - Volume de données élevé (exfiltration potentielle)

Suppose que extractor.py attache `packet["tls"]` du type :
    {"handshake_type": str|None, "alert": bool, "content_type": str}
pour le trafic identifié avec protocol == "HTTPS".
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

LONG_SESSION_MIN_SECONDS = 300.0
HIGH_VOLUME_MIN_BYTES = 50_000_000


def _https_packets(conversation: dict) -> list[dict]:
    return [p for p in conversation.get("packets", []) if p.get("protocol") == "HTTPS" and p.get("tls")]


def _identify_client_and_server(tls_packets: list[dict]) -> tuple[str | None, str | None]:
    """Le serveur est l'hôte qui répond avec un server_hello ; sinon, port 443/8443."""
    for p in tls_packets:
        if p["tls"].get("handshake_type") == "server_hello":
            return p.get("dst_ip"), p.get("src_ip")
    for p in tls_packets:
        if p.get("src_port") in (443, 8443):
            return p.get("dst_ip"), p.get("src_ip")
        if p.get("dst_port") in (443, 8443):
            return p.get("src_ip"), p.get("dst_ip")
    return None, None


class TlsFailedHandshakeRule(Rule):
    """Détecte une session TLS interrompue par une alerte avant tout échange applicatif."""
    name = "tls_failed_handshake"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        tls_packets = _https_packets(conversation)
        if not tls_packets:
            return []

        has_client_hello = any(p["tls"].get("handshake_type") == "client_hello" for p in tls_packets)
        has_server_hello = any(p["tls"].get("handshake_type") == "server_hello" for p in tls_packets)
        has_alert = any(p["tls"].get("alert") for p in tls_packets)
        has_app_data = any(p["tls"].get("content_type") == "application_data" for p in tls_packets)

        if not has_client_hello:
            return []
        if has_app_data:
            return []
        if not (has_alert or not has_server_hello):
            return []

        client, server = _identify_client_and_server(tls_packets)
        return [self._alert(
            conversation,
            f"Handshake TLS échoué entre {client} et {server} "
            f"(pas de données applicatives chiffrées observées)",
            Severity.MEDIUM,
            evidence={"has_server_hello": has_server_hello, "has_alert": has_alert},
            cible=server,
        )]


class LongTlsSessionRule(Rule):
    """Session HTTPS anormalement longue (canal de commande potentiel, tunnel)."""
    name = "https_long_session"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        tls_packets = _https_packets(conversation)
        if not tls_packets:
            return []

        duration = conversation.get("duration") or 0.0
        if duration < LONG_SESSION_MIN_SECONDS:
            return []

        client, server = _identify_client_and_server(tls_packets)
        return [self._alert(
            conversation,
            f"Session HTTPS longue : {duration:.0f}s entre {client} et {server}",
            Severity.LOW,
            evidence={"duration_seconds": duration},
            cible=server,
        )]


class HighVolumeTlsRule(Rule):
    """Volume de données échangées en HTTPS anormalement élevé."""
    name = "https_high_data_volume"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        tls_packets = _https_packets(conversation)
        if not tls_packets:
            return []

        total_bytes = conversation.get("total_bytes", 0)
        if total_bytes < HIGH_VOLUME_MIN_BYTES:
            return []

        client, server = _identify_client_and_server(tls_packets)
        severity = Severity.HIGH if total_bytes >= HIGH_VOLUME_MIN_BYTES * 4 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"Volume HTTPS élevé : {total_bytes / 1_000_000:.1f} MB entre {client} et {server}",
            severity,
            evidence={"total_bytes": total_bytes},
            cible=server,
        )]


RULES = [TlsFailedHandshakeRule(), LongTlsSessionRule(), HighVolumeTlsRule()]