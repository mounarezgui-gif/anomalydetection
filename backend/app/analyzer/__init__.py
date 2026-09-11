# backend/app/analyzer/__init__.py
"""
Analyzer package - Extraction et agrégation de trafic réseau.

extractor.py et aggregator.py exposent chacun une seule fonction publique
(extract_packets / aggregate_packets) plutôt que des classes : le package
reste volontairement simple, sans état à instancier.
"""

from .aggregator import aggregate_packets
from .extractor import (
    PacketExtractionError,
    extract_packets,
)
from .models import (
    CaptureSummary,
    ConversationRecord,
    HandshakeInfo,
    PacketRecord,
    PcapAnalysisResult,
    TCPInfo,
)

__all__ = [
    "CaptureSummary",
    "ConversationRecord",
    "HandshakeInfo",
    "PacketExtractionError",
    "PacketRecord",
    "PcapAnalysisResult",
    "TCPInfo",
    "aggregate_packets",
    "extract_packets",
]