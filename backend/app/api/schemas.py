"""
schemas.py
Modèles Pydantic pour les réponses de l'API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class DetectionSummary(BaseModel):
    total_alerts: int
    alerts_by_severity: dict[str, int]


class Alert(BaseModel):
    rule_id: str
    protocole: str
    cible: str
    severite: str
    description: str
    details: dict[str, Any]

    conversation_id: int | None = None
    packet_number: int | None = None
    timestamp: str


class AnalysisSummary(BaseModel):
    """Résumé léger, utilisé dans GET /analyses."""

    id: str
    filename: str
    created_at: datetime

    total_packets: int
    total_conversations: int

    detection_summary: DetectionSummary


class AnalysisDetail(BaseModel):
    """Résultat complet d'une analyse."""

    id: str
    filename: str
    created_at: datetime

    capture_summary: dict[str, Any]
    conversations: list[dict[str, Any]]

    alerts: list[Alert]

    detection_summary: DetectionSummary


class ErrorResponse(BaseModel):
    detail: str