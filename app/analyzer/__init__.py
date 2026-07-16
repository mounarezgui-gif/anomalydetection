# backend/app/analyzer/__init__.py
"""
Analyzer package - Extraction et agrégation de trafic réseau.

extractor.py et aggregator.py exposent chacun une seule fonction publique
(extract_packets / aggregate_packets) plutôt que des classes : le package
reste volontairement simple, sans état à instancier.
"""

from .extractor import (
    extract_packets,
    PacketExtractionError,
)
from .aggregator import aggregate_packets
from .models import (
    CaptureSummary,
    ConversationRecord,
    HandshakeInfo,
    PacketRecord,
    PcapAnalysisResult,
    TCPInfo,
)

__all__ = [
    # Extraction (extractor.py)
    "extract_packets",
    "PacketExtractionError",
    # Agrégation (aggregator.py)
    "aggregate_packets",
    # Modèles (models.py)
    "PcapAnalysisResult",
    "CaptureSummary",
    "ConversationRecord",
    "PacketRecord",
    "TCPInfo",
    "HandshakeInfo",
]