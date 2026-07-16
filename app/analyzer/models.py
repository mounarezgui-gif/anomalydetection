# models.py
"""
Data structures shared by extractor.py and aggregator.py.

These models are plain, framework-agnostic dataclasses (no FastAPI, no
ORM dependency) so the detection engine stays testable in isolation
before being wired into the web API / database layer.

The structure mirrors exactly the JSON produced by aggregator.py:

    CaptureSummary          -> capture_summary
    ConversationRecord      -> one entry of "conversations"
    PacketRecord            -> one entry of a conversation's "packets"
    TCPInfo / HandshakeInfo -> the "tcp" / "tcp.handshake" sub-objects

Compatible with Python 3.11+.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ============================================================================
# TCP sub-models
# ============================================================================

@dataclass
class HandshakeInfo:
    """3-way handshake state for one tcp.stream, computed by aggregator.py."""

    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "syn_seen": self.syn_seen,
            "syn_ack_seen": self.syn_ack_seen,
            "ack_seen": self.ack_seen,
            "completed": self.completed,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "HandshakeInfo":
        data = data or {}
        return cls(
            syn_seen=bool(data.get("syn_seen", False)),
            syn_ack_seen=bool(data.get("syn_ack_seen", False)),
            ack_seen=bool(data.get("ack_seen", False)),
            completed=bool(data.get("completed", False)),
        )


@dataclass
class TCPInfo:
    """Per-packet TCP details: flags + handshake state of its stream."""

    stream: Optional[int] = None
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    handshake: Optional[HandshakeInfo] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream": self.stream,
            "syn": self.syn,
            "ack": self.ack,
            "fin": self.fin,
            "rst": self.rst,
            "handshake": self.handshake.to_dict() if self.handshake else None,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["TCPInfo"]:
        if not data:
            return None
        return cls(
            stream=data.get("stream"),
            syn=bool(data.get("syn", False)),
            ack=bool(data.get("ack", False)),
            fin=bool(data.get("fin", False)),
            rst=bool(data.get("rst", False)),
            handshake=HandshakeInfo.from_dict(data.get("handshake")),
        )


# ============================================================================
# Packet model (Level 3)
# ============================================================================

@dataclass
class PacketRecord:
    """One packet, as found inside a conversation's "packets" list."""

    packet_number: int
    timestamp: Optional[float]
    relative_time: Optional[float]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length_bytes: int
    length_bits: int
    default_port: bool
    tcp: Optional[TCPInfo] = None
    timestamp_iso: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_number": self.packet_number,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "relative_time": self.relative_time,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length_bytes": self.length_bytes,
            "length_bits": self.length_bits,
            "default_port": self.default_port,
            "tcp": self.tcp.to_dict() if self.tcp else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketRecord":
        """Build a PacketRecord from one packet dict as produced by aggregator.py."""
        return cls(
            packet_number=data.get("packet_number", 0) or 0,
            timestamp=data.get("timestamp"),
            timestamp_iso=data.get("timestamp_iso"),
            relative_time=data.get("relative_time"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol", "UNKNOWN") or "UNKNOWN",
            length_bytes=data.get("length_bytes", 0) or 0,
            length_bits=data.get("length_bits", 0) or 0,
            default_port=bool(data.get("default_port", False)),
            tcp=TCPInfo.from_dict(data.get("tcp")),
        )


# ============================================================================
# Conversation model (Level 2)
# ============================================================================

@dataclass
class ConversationRecord:
    """One IP-pair conversation (endpointA <-> endpointB), direction-independent."""

    conversation_id: int
    ip_a: str
    ip_b: str
    ports: List[int] = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    total_bits: int = 0
    protocols_used: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: float = 0.0
    packets: List[PacketRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "ip_a": self.ip_a,
            "ip_b": self.ip_b,
            "ports": self.ports,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_bits": self.total_bits,
            "protocols_used": self.protocols_used,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "packets": [packet.to_dict() for packet in self.packets],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConversationRecord":
        """Build a ConversationRecord from one entry of aggregator.py's "conversations"."""
        return cls(
            conversation_id=data.get("conversation_id", 0) or 0,
            ip_a=data.get("ip_a", "") or "",
            ip_b=data.get("ip_b", "") or "",
            ports=list(data.get("ports") or []),
            total_packets=data.get("total_packets", 0) or 0,
            total_bytes=data.get("total_bytes", 0) or 0,
            total_bits=data.get("total_bits", 0) or 0,
            protocols_used=list(data.get("protocols_used") or []),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            duration=data.get("duration", 0.0) or 0.0,
            packets=[
                PacketRecord.from_dict(packet_data)
                for packet_data in (data.get("packets") or [])
            ],
        )


# ============================================================================
# Capture summary (Level 1)
# ============================================================================

@dataclass
class CaptureSummary:
    """Capture-wide statistics, matches aggregator.py's "capture_summary"."""

    total_packets: int = 0
    total_conversations: int = 0
    total_bytes: int = 0
    total_bits: int = 0
    protocols: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "total_conversations": self.total_conversations,
            "total_bytes": self.total_bytes,
            "total_bits": self.total_bits,
            "protocols": self.protocols,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureSummary":
        return cls(
            total_packets=data.get("total_packets", 0) or 0,
            total_conversations=data.get("total_conversations", 0) or 0,
            total_bytes=data.get("total_bytes", 0) or 0,
            total_bits=data.get("total_bits", 0) or 0,
            protocols=list(data.get("protocols") or []),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            duration=data.get("duration", 0.0) or 0.0,
        )


# ============================================================================
# Top-level analysis result
# ============================================================================

@dataclass
class PcapAnalysisResult:
    """Full result of aggregate_packets(): capture_summary + conversations."""

    capture_summary: CaptureSummary
    conversations: List[ConversationRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture_summary": self.capture_summary.to_dict(),
            "conversations": [conversation.to_dict() for conversation in self.conversations],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PcapAnalysisResult":
        """Build a PcapAnalysisResult from the raw dict returned by aggregate_packets()."""
        return cls(
            capture_summary=CaptureSummary.from_dict(data.get("capture_summary") or {}),
            conversations=[
                ConversationRecord.from_dict(conversation_data)
                for conversation_data in (data.get("conversations") or [])
            ],
        )


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "HandshakeInfo",
    "TCPInfo",
    "PacketRecord",
    "ConversationRecord",
    "CaptureSummary",
    "PcapAnalysisResult",
]