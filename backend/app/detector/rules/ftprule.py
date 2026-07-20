"""
ftprule.py
==========

Règles comportementales FTP :
  - Nombre de connexions anormal (multiplication de tcp.stream vers le port 21)
  - Échecs de connexion (codes de réponse 4xx/5xx FTP répétés)

Suppose que extractor.py attache `packet["ftp"]` du type :
    {"is_response": bool, "response_code": int|None, "command": str|None}
pour le trafic identifié sur le port de contrôle FTP (21).
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

FTP_MANY_CONNECTIONS_MIN_STREAMS = 10
FTP_FAILURE_MIN_RESPONSES = 5
FTP_FAILURE_MIN_RATIO = 0.5


def _ftp_streams(conversation: dict) -> set[int]:
    streams: set[int] = set()
    for p in conversation.get("packets", []):
        if p.get("ftp") and p.get("tcp") and p["tcp"].get("stream") is not None:
            if p.get("dst_port") == 21 or p.get("src_port") == 21:
                streams.add(p["tcp"]["stream"])
    return streams


class FtpManyConnectionsRule(Rule):
    """Nombre de connexions de contrôle FTP anormalement élevé entre deux hôtes."""
    name = "ftp_many_connections"
    protocol = "FTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        streams = _ftp_streams(conversation)
        if len(streams) < FTP_MANY_CONNECTIONS_MIN_STREAMS:
            return []

        return [self._alert(
            conversation,
            f"Nombre de connexions FTP élevé : {len(streams)} sessions entre "
            f"{conversation.get('ip_a')} et {conversation.get('ip_b')}",
            Severity.MEDIUM,
            evidence={"connection_count": len(streams)},
        )]


class FtpFailureRateRule(Rule):
    """Proportion élevée de réponses d'échec FTP (ex. bruteforce d'identifiants)."""
    name = "ftp_connection_failures"
    protocol = "FTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        responses = [
            p for p in conversation.get("packets", [])
            if p.get("ftp") and p["ftp"].get("is_response") and p["ftp"].get("response_code") is not None
        ]
        if len(responses) < FTP_FAILURE_MIN_RESPONSES:
            return []

        failures = [p for p in responses if p["ftp"]["response_code"] >= 400]
        ratio = len(failures) / len(responses)
        if ratio < FTP_FAILURE_MIN_RATIO:
            return []

        severity = Severity.HIGH if ratio >= 0.8 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"Taux d'échec FTP élevé : {len(failures)}/{len(responses)} ({ratio:.0%}) "
            f"depuis {conversation.get('ip_a')}",
            severity,
            evidence={"failure_ratio": round(ratio, 2), "failure_count": len(failures)},
        )]


RULES = [FtpManyConnectionsRule(), FtpFailureRateRule()]