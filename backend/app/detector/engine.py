"""
engine.py
=========

Point d'entrée du moteur de détection basé sur des règles comportementales.

Consomme le JSON produit par aggregator.py (capture_summary + conversations)
et fait passer chaque conversation à travers l'ensemble des règles
pertinentes (déterminées par conversation["protocols_used"]).

Usage :
    python -m detector.engine capture_analysis.json
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .rules import (
    dhcprule,
    dnsrule,
    ftprule,
    httprule,
    httpsrule,
    icmprule,
    portrule,
    sshrule,
    tcprule,
    udprule,
)
from .rules.common import Alert, Rule

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Toutes les règles disponibles, peu importe le protocole : chaque règle
# se filtre elle-même via conversation["protocols_used"] / les champs
# présents sur les paquets. Ça simplifie l'ajout d'une nouvelle règle :
# il suffit de l'ajouter à la liste RULES de son module.
ALL_RULES: list[Rule] = [
    *tcprule.RULES,
    *udprule.RULES,
    *dnsrule.RULES,
    *httprule.RULES,
    *httpsrule.RULES,
    *ftprule.RULES,
    *sshrule.RULES,
    *icmprule.RULES,
    *dhcprule.RULES,
    *portrule.RULES,
]


def run_rules(conversations: Iterable[dict], rules: list[Rule] = ALL_RULES) -> list[Alert]:
    """Exécute toutes les règles sur toutes les conversations et agrège les alertes."""
    alerts: list[Alert] = []
    for conversation in conversations:
        for rule in rules:
            try:
                alerts.extend(rule.evaluate(conversation))
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[engine] règle '{rule.name}' en erreur sur la conversation "
                    f"{conversation.get('conversation_id')}: {exc}",
                    file=sys.stderr,
                )
    return alerts


def analyze(aggregated: dict, rules: list[Rule] = ALL_RULES) -> dict:
    """
    Prend la structure produite par aggregator.aggregate_packets() et retourne
    une structure enrichie avec les alertes détectées.
    """
    conversations = aggregated.get("conversations", [])
    alerts = run_rules(conversations, rules)  # déjà des dicts au format alert.make_alert()

    alerts_by_severity: dict[str, int] = {}
    for alert in alerts:
        severite = alert["severite"]
        alerts_by_severity[severite] = alerts_by_severity.get(severite, 0) + 1

    return {
        "capture_summary": aggregated.get("capture_summary"),
        "detection_summary": {
            "total_alerts": len(alerts),
            "alerts_by_severity": alerts_by_severity,
        },
        "alerts": alerts,
        "conversations": conversations,
    }


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python -m app.detector.engine <nom_fichier.json>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    candidates = (
        (input_path,) if input_path.is_absolute() else (
            Path.cwd() / input_path,
            PROJECT_ROOT / input_path,
            PROJECT_ROOT / "samples" / input_path,
        )
    )
    json_path = next((candidate for candidate in candidates if candidate.exists()), None)

    if json_path is None:
        print(f"Fichier introuvable : {input_path}")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        aggregated_data = json.load(f)

    result = analyze(aggregated_data)

    # Création du dossier alerts
    alerts_dir = Path("alerts")
    alerts_dir.mkdir(exist_ok=True)

    # Nom unique basé sur la date et l'heure
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    output_path = alerts_dir / f"detection_result_{timestamp}.json"

    # Sauvegarde
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(f"Résultat sauvegardé dans : {output_path}")