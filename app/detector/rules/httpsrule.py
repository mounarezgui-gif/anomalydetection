"""
httpsrule.py
============

Règles comportementales HTTPS/TLS :
  - Handshake TLS échoué (alert/reset avant ApplicationData)
  - Sessions longues
  - Volume de données élevé (exfiltration potentielle)

Suppose que extractor.py attache `packet["tls"]` du type :
    {"handshake_type": str|None, "alert": bool, "content_type": str}
Si absent, ces règles retournent simplement une liste vide (dégradation
silencieuse, pas de crash).
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

LONG_SESSION_MIN_SECONDS = 300.0     # 5 minutes
HIGH_VOLUME_MIN_BYTES = 50_000_000   # 50 MB


class TlsFailedHandshakeRule(Rule):
    """Détecte une session TLS interrompue par une alerte avant tout échange applicatif."""
    name = "tls_failed_handshake"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        tls_packets = [p for p in conversation.get("packets", []) if p.get("tls")]
        if not tls_packets:
            return []

        has_client_hello = any(p["tls"].get("handshake_type") == "client_hello" for p in tls_packets)
        has_server_hello = any(p["tls"].get("handshake_type") == "server_hello" for p in tls_packets)
        has_alert = any(p["tls"].get("alert") for p in tls_packets)
        has_app_data = any(p["tls"].get("content_type") == "application_data" for p in tls_packets)

        if not has_client_hello:
            return []
        if has_app_data:
            return []  # la session a fini par établir un canal chiffré fonctionnel
        if not (has_alert or not has_server_hello):
            return []

        return [self._alert(
            conversation,
            f"Handshake TLS échoué entre {conversation.get('ip_a')} et {conversation.get('ip_b')} "
            f"(pas de données applicatives chiffrées observées)",
            Severity.MEDIUM,
            evidence={"has_server_hello": has_server_hello, "has_alert": has_alert},
        )]


class LongTlsSessionRule(Rule):
    """Session HTTPS anormalement longue (canal de commande potentiel, tunnel)."""
    name = "https_long_session"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if not any(p.get("tls") for p in conversation.get("packets", [])):
            return []

        duration = conversation.get("duration") or 0.0
        if duration < LONG_SESSION_MIN_SECONDS:
            return []

        return [self._alert(
            conversation,
            f"Session HTTPS longue : {duration:.0f}s entre {conversation.get('ip_a')} "
            f"et {conversation.get('ip_b')}",
            Severity.LOW,
            evidence={"duration_seconds": duration},
        )]


class HighVolumeTlsRule(Rule):
    """Volume de données échangées en HTTPS anormalement élevé."""
    name = "https_high_data_volume"
    protocol = "HTTPS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        if not any(p.get("tls") for p in conversation.get("packets", [])):
            return []

        total_bytes = conversation.get("total_bytes", 0)
        if total_bytes < HIGH_VOLUME_MIN_BYTES:
            return []

        severity = Severity.HIGH if total_bytes >= HIGH_VOLUME_MIN_BYTES * 4 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"Volume HTTPS élevé : {total_bytes / 1_000_000:.1f} MB entre "
            f"{conversation.get('ip_a')} et {conversation.get('ip_b')}",
            severity,
            evidence={"total_bytes": total_bytes},
        )]


RULES = [TlsFailedHandshakeRule(), LongTlsSessionRule(), HighVolumeTlsRule()]