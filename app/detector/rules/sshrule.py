"""
sshrule.py
==========

Règles comportementales SSH :
  - Durée de session anormale (trop courte -> tentative automatisée /
    trop longue -> session interactive suspecte)
  - Tentatives répétées (multiplication de tcp.stream vers le port 22)
  - Bruteforce (beaucoup de sessions courtes et rapprochées dans le temps)

Repose uniquement sur les métadonnées TCP (SSH est chiffré dès l'échange
de clés : on ne voit pas les identifiants, seulement les motifs de
connexion), donc pas besoin d'un champ "ssh" applicatif dédié.
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

SSH_PORT = 22
SHORT_SESSION_MAX_SECONDS = 2.0     # une session SSH légitime dure rarement < 2s
LONG_SESSION_MIN_SECONDS = 3600.0   # 1h
BRUTEFORCE_MIN_ATTEMPTS = 8
BRUTEFORCE_WINDOW_SECONDS = 60.0


def _ssh_streams(conversation: dict) -> dict[int, list[dict]]:
    streams: dict[int, list[dict]] = {}
    for p in conversation.get("packets", []):
        if p.get("dst_port") != SSH_PORT and p.get("src_port") != SSH_PORT:
            continue
        tcp = p.get("tcp")
        if not tcp or tcp.get("stream") is None:
            continue
        streams.setdefault(tcp["stream"], []).append(p)
    return streams


class SshRepeatedAttemptsRule(Rule):
    """Nombre de tentatives de connexion SSH (streams distincts) anormalement élevé."""
    name = "ssh_repeated_attempts"
    protocol = "SSH"

    def evaluate(self, conversation: dict) -> list[Alert]:
        streams = _ssh_streams(conversation)
        if len(streams) < BRUTEFORCE_MIN_ATTEMPTS:
            return []

        return [self._alert(
            conversation,
            f"Tentatives SSH répétées : {len(streams)} connexions distinctes depuis "
            f"{conversation.get('ip_a')} vers {conversation.get('ip_b')}",
            Severity.MEDIUM,
            evidence={"attempt_count": len(streams)},
        )]


class SshBruteforceRule(Rule):
    """
    Beaucoup de sessions SSH courtes (échec d'authentification probable)
    concentrées sur une fenêtre de temps courte -> bruteforce.
    """
    name = "ssh_bruteforce"
    protocol = "SSH"

    def evaluate(self, conversation: dict) -> list[Alert]:
        streams = _ssh_streams(conversation)
        if len(streams) < BRUTEFORCE_MIN_ATTEMPTS:
            return []

        short_session_starts: list[float] = []
        for stream_packets in streams.values():
            timestamps = [p["timestamp"] for p in stream_packets if p.get("timestamp") is not None]
            if not timestamps:
                continue
            duration = max(timestamps) - min(timestamps)
            if duration <= SHORT_SESSION_MAX_SECONDS:
                short_session_starts.append(min(timestamps))

        if len(short_session_starts) < BRUTEFORCE_MIN_ATTEMPTS:
            return []

        short_session_starts.sort()
        left = 0
        max_in_window = 1
        for right in range(len(short_session_starts)):
            while short_session_starts[right] - short_session_starts[left] > BRUTEFORCE_WINDOW_SECONDS:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < BRUTEFORCE_MIN_ATTEMPTS:
            return []

        return [self._alert(
            conversation,
            f"Bruteforce SSH suspecté : {max_in_window} sessions courtes en moins de "
            f"{BRUTEFORCE_WINDOW_SECONDS:.0f}s depuis {conversation.get('ip_a')}",
            Severity.CRITICAL,
            evidence={"short_sessions_in_window": max_in_window, "total_short_sessions": len(short_session_starts)},
        )]


class SshSessionDurationRule(Rule):
    """Sessions SSH anormalement longues (canal interactif ou tunnel prolongé)."""
    name = "ssh_long_session"
    protocol = "SSH"

    def evaluate(self, conversation: dict) -> list[Alert]:
        streams = _ssh_streams(conversation)
        alerts: list[Alert] = []
        for stream_id, stream_packets in streams.items():
            timestamps = [p["timestamp"] for p in stream_packets if p.get("timestamp") is not None]
            if not timestamps:
                continue
            duration = max(timestamps) - min(timestamps)
            if duration >= LONG_SESSION_MIN_SECONDS:
                alerts.append(self._alert(
                    conversation,
                    f"Session SSH longue (stream {stream_id}) : {duration / 60:.0f} min entre "
                    f"{conversation.get('ip_a')} et {conversation.get('ip_b')}",
                    Severity.LOW,
                    evidence={"stream_id": stream_id, "duration_seconds": duration},
                ))
        return alerts


RULES = [SshRepeatedAttemptsRule(), SshBruteforceRule(), SshSessionDurationRule()]