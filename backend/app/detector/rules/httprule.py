"""
httprule.py
===========

Règles comportementales HTTP :
  - HTTP Flood (débit de requêtes anormal)
  - Nombre de GET/POST (déséquilibre ou volume suspect)
  - Codes 404/500 anormaux (scan de contenu / instabilité serveur)

Suppose que extractor.py attache `packet["http"]` du type :
    {"method": "GET"|"POST"|..., "status_code": int|None}
pour le trafic identifié avec protocol == "HTTP".

Le serveur/la cible sont déterminés à partir des src_ip/dst_ip réels des
paquets, jamais depuis ip_a/ip_b de la conversation (sans direction
garantie).
"""

from __future__ import annotations

from collections import Counter

from .common import Rule, Severity, Alert

HTTP_FLOOD_MIN_REQUESTS = 100
HTTP_FLOOD_MIN_RPS = 20.0
POST_HEAVY_MIN_REQUESTS = 30
POST_HEAVY_MIN_RATIO = 0.8
ERROR_RATE_MIN_RESPONSES = 20
ERROR_RATE_MIN_RATIO = 0.3


def _http_requests(conversation: dict) -> list[dict]:
    return [
        p for p in conversation.get("packets", [])
        if p.get("protocol") == "HTTP" and p.get("http") and p["http"].get("method")
    ]


def _http_responses(conversation: dict) -> list[dict]:
    return [
        p for p in conversation.get("packets", [])
        if p.get("protocol") == "HTTP" and p.get("http") and p["http"].get("status_code")
    ]


def _identify_server(packets: list[dict]) -> str | None:
    """
    Pour des requêtes : le serveur est la destination majoritaire.
    Pour des réponses : le serveur est la source majoritaire.
    On combine les deux pour couvrir les deux cas d'usage du fichier.
    """
    counts: dict[str, int] = {}
    for p in packets:
        for ip in (p.get("dst_ip"), p.get("src_ip")):
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
    return max(counts, key=counts.get) if counts else None


class HttpFloodRule(Rule):
    """Débit de requêtes HTTP anormalement élevé (déni de service applicatif)."""
    name = "http_flood"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        requests = _http_requests(conversation)
        if len(requests) < HTTP_FLOOD_MIN_REQUESTS:
            return []

        duration = conversation.get("duration") or 0.0
        if duration <= 0:
            return []

        rps = len(requests) / duration
        if rps < HTTP_FLOOD_MIN_RPS:
            return []

        server = _identify_server(requests)
        severity = Severity.CRITICAL if rps >= HTTP_FLOOD_MIN_RPS * 3 else Severity.HIGH
        return [self._alert(
            conversation,
            f"HTTP flood suspecté : {rps:.1f} requêtes/s ({len(requests)} requêtes) "
            f"vers {server}",
            severity,
            evidence={"request_count": len(requests), "rps": round(rps, 2)},
            cible=server,
        )]


class HttpMethodDistributionRule(Rule):
    """
    Volume de GET/POST et déséquilibre suspect (ex. rafale de POST typique
    d'un bruteforce de formulaire de connexion ou d'une exfiltration).
    """
    name = "http_method_distribution"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        requests = _http_requests(conversation)
        if len(requests) < POST_HEAVY_MIN_REQUESTS:
            return []

        methods = Counter(p["http"]["method"] for p in requests)
        post_count = methods.get("POST", 0)
        ratio = post_count / len(requests)

        if ratio < POST_HEAVY_MIN_RATIO:
            return []

        server = _identify_server(requests)
        return [self._alert(
            conversation,
            f"Rafale de requêtes POST suspecte : {post_count}/{len(requests)} "
            f"({ratio:.0%}) vers {server}",
            Severity.MEDIUM,
            evidence={"methods": dict(methods), "post_ratio": round(ratio, 2)},
            cible=server,
        )]


class HttpErrorRateRule(Rule):
    """Proportion anormale de réponses 4xx/5xx (scan de contenu ou instabilité)."""
    name = "http_abnormal_error_rate"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        responses = _http_responses(conversation)
        if len(responses) < ERROR_RATE_MIN_RESPONSES:
            return []

        errors = [p for p in responses if p["http"]["status_code"] >= 400]
        ratio = len(errors) / len(responses)
        if ratio < ERROR_RATE_MIN_RATIO:
            return []

        server = _identify_server(responses)
        status_counts = Counter(p["http"]["status_code"] for p in errors)
        severity = Severity.HIGH if ratio >= 0.6 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"Taux d'erreurs HTTP anormal : {len(errors)}/{len(responses)} "
            f"({ratio:.0%}) réponses 4xx/5xx depuis {server}",
            severity,
            evidence={"error_ratio": round(ratio, 2), "status_codes": dict(status_counts)},
            cible=server,
        )]


RULES = [HttpFloodRule(), HttpMethodDistributionRule(), HttpErrorRateRule()]