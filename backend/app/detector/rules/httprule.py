from __future__ import annotations
from collections import Counter
from .common import Rule, Severity, Alert

# Configuration
HTTP_FLOOD_MIN_REQ = 50
HTTP_FLOOD_WINDOW = 5.0
HTTP_FLOOD_MIN_RPS = 20.0

POST_HEAVY_MIN_REQ = 30
POST_HEAVY_MIN_RATIO = 0.8

ERROR_RATE_MIN_RESP = 20
ERROR_RATE_MIN_RATIO = 0.3

def _identify_server(requests: list[dict], responses: list[dict]) -> str | None:
    """Identifie le serveur : IP destination des requêtes ou source des réponses."""
    ip_candidates = []
    for p in requests:
        if p.get("dst_ip"): ip_candidates.append(p["dst_ip"])
    for p in responses:
        if p.get("src_ip"): ip_candidates.append(p["src_ip"])
    
    if not ip_candidates:
        return None
    return Counter(ip_candidates).most_common(1)[0][0]

class HttpFloodRule(Rule):
    """Détecte un pic de requêtes HTTP (DoS applicatif) via une fenêtre glissante."""
    name = "http_flood"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        packets = conversation.get("packets", [])
        # On ne garde que les requêtes avec timestamp
        requests = [
            p for p in packets 
            if p.get("protocol") == "HTTP" and p.get("http", {}).get("method") and p.get("timestamp")
        ]

        if len(requests) < HTTP_FLOOD_MIN_REQ:
            return []

        # Algorithme de fenêtre glissante pour trouver le RPS maximum
        requests.sort(key=lambda p: p["timestamp"])
        max_req_in_window = 0
        left = 0
        for right in range(len(requests)):
            while requests[right]["timestamp"] - requests[left]["timestamp"] > HTTP_FLOOD_WINDOW:
                left += 1
            max_req_in_window = max(max_req_in_window, right - left + 1)

        rps = max_req_in_window / HTTP_FLOOD_WINDOW
        if rps < HTTP_FLOOD_MIN_RPS:
            return []

        server = _identify_server(requests, [])
        severity = Severity.CRITICAL if rps >= HTTP_FLOOD_MIN_RPS * 4 else Severity.HIGH
        
        return [self._alert(
            conversation,
            f"HTTP Flood : {rps:.1f} req/s détectées vers {server}",
            severity,
            evidence={"max_rps": round(rps, 2), "total_requests": len(requests)},
            cible=server
        )]

class HttpMethodDistributionRule(Rule):
    """Détecte un abus de méthode POST (Bruteforce ou Exfiltration)."""
    name = "http_method_distribution"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        requests = [p for p in conversation.get("packets", []) 
                    if p.get("protocol") == "HTTP" and p.get("http", {}).get("method")]
        
        if len(requests) < POST_HEAVY_MIN_REQ:
            return []

        method_counts = Counter(p["http"]["method"] for p in requests)
        post_count = method_counts.get("POST", 0)
        ratio = post_count / len(requests)

        if ratio < POST_HEAVY_MIN_RATIO:
            return []

        server = _identify_server(requests, [])
        return [self._alert(
            conversation,
            f"Distribution HTTP suspecte : {ratio:.0%} de POST vers {server}",
            Severity.MEDIUM,
            evidence={"methods": dict(method_counts), "ratio_post": round(ratio, 2)},
            cible=server
        )]

class HttpErrorRateRule(Rule):
    """Détecte un taux anormal de codes 4xx (scan) ou 5xx (instabilité)."""
    name = "http_abnormal_error_rate"
    protocol = "HTTP"

    def evaluate(self, conversation: dict) -> list[Alert]:
        responses = [p for p in conversation.get("packets", []) 
                     if p.get("protocol") == "HTTP" and p.get("http", {}).get("status_code")]
        
        if len(responses) < ERROR_RATE_MIN_RESP:
            return []

        error_responses = [p for p in responses if p["http"]["status_code"] >= 400]
        ratio = len(error_responses) / len(responses)

        if ratio < ERROR_RATE_MIN_RATIO:
            return []

        status_counts = Counter(p["http"]["status_code"] for p in error_responses)
        server = _identify_server([], responses)
        
        # Si beaucoup de 404 -> Scan. Si beaucoup de 500 -> Panne/Exploitation.
        most_common_error = status_counts.most_common(1)[0][0]
        severity = Severity.HIGH if ratio > 0.7 else Severity.MEDIUM

        return [self._alert(
            conversation,
            f"Taux d'erreurs HTTP élevé ({ratio:.0%}) depuis {server} (Code majoritaire: {most_common_error})",
            severity,
            evidence={"status_codes": dict(status_counts), "error_ratio": round(ratio, 2)},
            cible=server
        )]

RULES = [HttpFloodRule(), HttpMethodDistributionRule(), HttpErrorRateRule()]