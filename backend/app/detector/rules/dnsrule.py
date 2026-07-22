"""
dnsrule.py
==========

Règles comportementales DNS :
  - Débit DNS anormal (requêtes/seconde)
  - DNS Flood (rafale de requêtes DNS, ex. amplification/exfiltration)

Suppose que extractor.py attache un sous-dict `packet["dns"]` du type :
    {"is_query": bool, "is_response": bool, "qname": str}
pour les paquets identifiés comme protocol == "DNS".

L'IP à l'origine des requêtes est déterminée à partir des src_ip réels
des paquets DNS de type requête, jamais depuis ip_a/ip_b de la
conversation : ces derniers n'ont pas de sens directionnel garanti
(assignés arbitrairement par aggregator.py) et pourraient afficher le
serveur DNS comme "source" au lieu du client.
"""

from __future__ import annotations

from .common import Rule, Severity, Alert

DNS_HIGH_RATE_MIN_QUERIES = 50
DNS_HIGH_RATE_MIN_QPS = 20.0       # requêtes/seconde
DNS_FLOOD_MIN_QUERIES = 200
DNS_FLOOD_WINDOW_SECONDS = 2.0


def _dns_queries(conversation: dict) -> list[dict]:
    return [
        p for p in conversation.get("packets", [])
        if p.get("protocol") == "DNS" and p.get("dns") and p["dns"].get("is_query")
    ]


def _identify_source(queries: list[dict]) -> str | None:
    """
    Détermine l'IP à l'origine des requêtes DNS (le client qui interroge),
    en comptant les src_ip réels des paquets de type requête plutôt que
    de se fier à ip_a/ip_b de la conversation.
    """
    src_counts: dict[str, int] = {}
    for p in queries:
        if p.get("src_ip"):
            src_counts[p["src_ip"]] = src_counts.get(p["src_ip"], 0) + 1
    return max(src_counts, key=src_counts.get) if src_counts else None


class DnsHighRateRule(Rule):
    """Débit de requêtes DNS anormalement élevé sur la conversation."""
    name = "dns_high_query_rate"
    protocol = "DNS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        queries = _dns_queries(conversation)
        if len(queries) < DNS_HIGH_RATE_MIN_QUERIES:
            return []

        duration = conversation.get("duration") or 0.0
        if duration <= 0:
            return []

        qps = len(queries) / duration
        if qps < DNS_HIGH_RATE_MIN_QPS:
            return []

        source = _identify_source(queries)
        severity = Severity.HIGH if qps >= DNS_HIGH_RATE_MIN_QPS * 3 else Severity.MEDIUM
        return [self._alert(
            conversation,
            f"Débit DNS élevé : {qps:.1f} requêtes/s ({len(queries)} requêtes) "
            f"depuis {source}",
            severity,
            evidence={"query_count": len(queries), "qps": round(qps, 2), "source": source},
            cible=source,
        )]


class DnsFloodRule(Rule):
    """Rafale de requêtes DNS concentrée sur une très courte fenêtre."""
    name = "dns_flood"
    protocol = "DNS"

    def evaluate(self, conversation: dict) -> list[Alert]:
        queries = _dns_queries(conversation)
        if len(queries) < DNS_FLOOD_MIN_QUERIES:
            return []

        timestamps = sorted(p["timestamp"] for p in queries if p.get("timestamp") is not None)
        if not timestamps:
            return []

        left = 0
        max_in_window = 1
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > DNS_FLOOD_WINDOW_SECONDS:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window < DNS_FLOOD_MIN_QUERIES:
            return []

        source = _identify_source(queries)
        return [self._alert(
            conversation,
            f"DNS flood suspecté : {max_in_window} requêtes en moins de "
            f"{DNS_FLOOD_WINDOW_SECONDS}s depuis {source}",
            Severity.CRITICAL,
            evidence={"max_queries_in_window": max_in_window, "source": source},
            cible=source,
        )]


RULES = [DnsHighRateRule(), DnsFloodRule()]