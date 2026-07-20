"""
common.py
=========

Socle partagé par toutes les règles de détection comportementale.

Ne redéfinit plus son propre format d'alerte : délègue à
detector.alert.make_alert(), qui est le format standard partagé par
toutes les règles du moteur (réputation, comportementales, etc.).

Contenu :
- Severity : niveaux de gravité internes aux règles (plus fins à écrire
  que INFO/WARNING/SUSPICIOUS/CRITICAL), mappés vers les SEVERITY_LEVELS
  de alert.py au moment de la construction de l'alerte.
- Alert : alias de type = dict (le format retourné par make_alert()).
- Rule : interface commune (une règle = un objet qui évalue UNE
  conversation et retourne 0..N alertes déjà au format make_alert()).

Toutes les règles reçoivent une "conversation" telle que produite par
aggregator.py (dict avec ip_a, ip_b, ports, total_packets, total_bytes,
duration, protocols_used, packets: [...]).

Compatible Python 3.11+.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from ..alert import make_alert


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Correspondance entre les niveaux internes des règles et les
# SEVERITY_LEVELS attendus par alert.make_alert() ("INFO", "WARNING",
# "SUSPICIOUS", "CRITICAL").
_SEVERITY_TO_ALERT_LEVEL: dict[Severity, str] = {
    Severity.LOW: "INFO",
    Severity.MEDIUM: "WARNING",
    Severity.HIGH: "SUSPICIOUS",
    Severity.CRITICAL: "CRITICAL",
}

# Alias de type : une "Alert" est désormais le dict standard retourné par
# make_alert() — plus une classe dédiée. Ça garde les mêmes annotations
# (list[Alert]) dans tous les fichiers de règles sans rien changer d'autre.
Alert = dict


class Rule:
    """
    Interface commune. Chaque règle concrète :
      - déclare `name` et `protocol` (utilisés comme rule_id / protocole)
      - implémente `evaluate(conversation) -> list[Alert]`

    Une règle ne doit JAMAIS lever d'exception sur une conversation mal
    formée : elle doit simplement ne rien retourner (liste vide) si les
    champs attendus sont absents. C'est le rôle du moteur (engine.py) de
    garantir la robustesse globale, mais chaque règle reste défensive.
    """

    name: str = "base_rule"
    protocol: str = "generic"

    def evaluate(self, conversation: dict) -> list[Alert]:
        raise NotImplementedError

    def _alert(
        self,
        conversation: dict,
        description: str,
        severity: Severity,
        evidence: Optional[dict] = None,
        packet_number: Optional[int] = None,
        cible: Optional[str] = None,
    ) -> Alert:
        """Raccourci pour construire une alerte au format standard alert.make_alert()."""
        target = cible or conversation.get("ip_b") or conversation.get("ip_a")
        return make_alert(
            rule_id=self.name,
            protocole=self.protocol,
            cible=target,
            severite=_SEVERITY_TO_ALERT_LEVEL[severity],
            description=description,
            details=evidence or {},
            conversation_id=conversation.get("conversation_id"),
            packet_number=packet_number,
        )


def packets_for_protocol(conversation: dict, predicate) -> list[dict]:
    """Filtre les paquets d'une conversation selon un prédicat arbitraire."""
    return [p for p in conversation.get("packets", []) if predicate(p)]