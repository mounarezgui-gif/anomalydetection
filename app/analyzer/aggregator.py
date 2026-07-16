"""
aggregator.py
=============

Consumes the flat list of packet dictionaries produced by extractor.py and
builds a hierarchical JSON structure:

    capture_summary
    conversations
        -> packets

A "conversation" is defined as all traffic exchanged between two IP
addresses, regardless of direction (endpointA <-> endpointB). This is
intentionally different from TCP/UDP streams: tcp.stream is used ONLY to
reconstruct the TCP 3-way handshake state for each TCP packet, never to
group conversations.

Compatible with Python 3.11+.
"""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from typing import Iterable, Optional


# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------


def _to_iso(timestamp: Optional[float]) -> Optional[str]:
    """Convert a UNIX epoch timestamp to an ISO-8601 UTC string."""
    if timestamp is None:
        return None
    try:
        return (
            _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return None


def _conversation_key(src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[tuple[str, str]]:
    """
    Build a direction-independent key for a conversation.

    Returns a sorted tuple (ip_a, ip_b) so that A->B and B->A packets map
    to the same conversation. Returns None when either IP is missing
    (e.g. non-IP traffic such as ARP), since such packets cannot be
    attributed to an IP conversation.
    """
    if not src_ip or not dst_ip:
        return None
    return tuple(sorted((src_ip, dst_ip)))  # type: ignore[return-value]


# --------------------------------------------------------------------------
# TCP handshake reconstruction
# --------------------------------------------------------------------------


def _compute_tcp_handshakes(packets: Iterable[dict]) -> dict[int, dict]:
    """
    Reconstruct, for every tcp.stream identifier, whether a full 3-way
    handshake (SYN -> SYN/ACK -> ACK) was observed in the capture.

    tcp.stream is used here strictly as a correlation key for handshake
    detection; it plays no role in conversation grouping.

    Returns:
        A mapping {tcp_stream_id: {syn_seen, syn_ack_seen, ack_seen, completed}}.
    """
    streams: dict[int, list[dict]] = defaultdict(list)

    for packet in packets:
        tcp_info = packet.get("tcp")
        if not tcp_info:
            continue
        stream_id = tcp_info.get("stream")
        if stream_id is None:
            continue
        streams[stream_id].append(packet)

    handshakes: dict[int, dict] = {}

    for stream_id, stream_packets in streams.items():
        # Process in capture order so SYN -> SYN/ACK -> ACK is detected
        # in the correct sequence.
        ordered = sorted(stream_packets, key=lambda p: p["packet_number"])

        syn_seen = False
        syn_ack_seen = False
        ack_seen = False

        for packet in ordered:
            flags = packet["tcp"]
            is_syn = flags.get("syn", False)
            is_ack = flags.get("ack", False)

            if is_syn and not is_ack and not syn_seen:
                syn_seen = True
            elif is_syn and is_ack and syn_seen and not syn_ack_seen:
                syn_ack_seen = True
            elif is_ack and not is_syn and syn_ack_seen and not ack_seen:
                ack_seen = True

        handshakes[stream_id] = {
            "syn_seen": syn_seen,
            "syn_ack_seen": syn_ack_seen,
            "ack_seen": ack_seen,
            "completed": syn_seen and syn_ack_seen and ack_seen,
        }

    return handshakes


def _attach_handshakes(packets: list[dict], handshakes: dict[int, dict]) -> None:
    """Mutate each TCP packet in-place to add its handshake info."""
    for packet in packets:
        tcp_info = packet.get("tcp")
        if not tcp_info:
            continue
        stream_id = tcp_info.get("stream")
        tcp_info["handshake"] = handshakes.get(
            stream_id,
            {
                "syn_seen": False,
                "syn_ack_seen": False,
                "ack_seen": False,
                "completed": False,
            },
        )


# --------------------------------------------------------------------------
# Packet-level formatting (Level 3)
# --------------------------------------------------------------------------


def _format_packet(packet: dict) -> dict:
    """Project an internal packet dict into the final Level-3 JSON schema."""
    return {
        "packet_number": packet["packet_number"],
        "timestamp": packet["timestamp"],
        "timestamp_iso": _to_iso(packet["timestamp"]),
        "relative_time": packet["relative_time"],
        "src_ip": packet["src_ip"],
        "dst_ip": packet["dst_ip"],
        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"],
        "protocol": packet["protocol"],
        "length_bytes": packet["length_bytes"],
        "length_bits": packet["length_bits"],
        "default_port": packet["default_port"],
        "tcp": packet["tcp"],  # None for non-TCP packets
    }


# --------------------------------------------------------------------------
# Conversation aggregation (Level 2)
# --------------------------------------------------------------------------


def _build_conversation(
    conversation_id: int,
    ip_a: str,
    ip_b: str,
    packets: list[dict],
) -> dict:
    """Aggregate a list of packets belonging to the same IP pair."""
    ports: set[int] = set()
    protocols_used: set[str] = set()
    total_bytes = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    formatted_packets: list[dict] = []

    # Sort by packet_number to guarantee chronological order within the
    # conversation regardless of the input ordering.
    for packet in sorted(packets, key=lambda p: p["packet_number"]):
        if packet["src_port"] is not None:
            ports.add(packet["src_port"])
        if packet["dst_port"] is not None:
            ports.add(packet["dst_port"])

        protocols_used.add(packet["protocol"])
        total_bytes += packet["length_bytes"]

        timestamp = packet["timestamp"]
        if timestamp is not None:
            start_time = timestamp if start_time is None else min(start_time, timestamp)
            end_time = timestamp if end_time is None else max(end_time, timestamp)

        formatted_packets.append(_format_packet(packet))

    duration = (end_time - start_time) if (start_time is not None and end_time is not None) else 0.0

    return {
        "conversation_id": conversation_id,
        "ip_a": ip_a,
        "ip_b": ip_b,
        "ports": sorted(ports),
        "total_packets": len(formatted_packets),
        "total_bytes": total_bytes,
        "total_bits": total_bytes * 8,
        "protocols_used": sorted(protocols_used),
        "start_time": _to_iso(start_time),
        "end_time": _to_iso(end_time),
        "duration": duration,
        "packets": formatted_packets,
    }


def _build_conversations(packets: list[dict]) -> list[dict]:
    """Group packets by direction-independent IP pair and aggregate each group."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    non_ip_packet_count = 0

    for packet in packets:
        key = _conversation_key(packet["src_ip"], packet["dst_ip"])
        if key is None:
            # Packets without both a source and destination IP (e.g. ARP)
            # cannot belong to an IP conversation; they are still counted
            # in the global capture summary but excluded here.
            non_ip_packet_count += 1
            continue
        groups[key].append(packet)

    conversations = [
        _build_conversation(conversation_id=idx, ip_a=key[0], ip_b=key[1], packets=group_packets)
        for idx, (key, group_packets) in enumerate(groups.items(), start=1)
    ]

    # Sort by descending packet count, as required.
    conversations.sort(key=lambda c: c["total_packets"], reverse=True)

    return conversations


# --------------------------------------------------------------------------
# Capture summary (Level 1)
# --------------------------------------------------------------------------


def _build_capture_summary(packets: list[dict], conversation_count: int) -> dict:
    """Compute global statistics over the whole capture."""
    total_packets = len(packets)
    total_bytes = sum(p["length_bytes"] for p in packets)
    protocols = sorted({p["protocol"] for p in packets})

    timestamps = [p["timestamp"] for p in packets if p["timestamp"] is not None]
    start_time = min(timestamps) if timestamps else None
    end_time = max(timestamps) if timestamps else None
    duration = (end_time - start_time) if (start_time is not None and end_time is not None) else 0.0

    return {
        "total_packets": total_packets,
        "total_conversations": conversation_count,
        "total_bytes": total_bytes,
        "total_bits": total_bytes * 8,
        "protocols": protocols,
        "start_time": _to_iso(start_time),
        "end_time": _to_iso(end_time),
        "duration": duration,
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def aggregate_packets(packets: list[dict]) -> dict:
    """
    Build the final hierarchical JSON structure from a flat packet list.

    Args:
        packets: The list of packet dictionaries produced by
            extractor.extract_packets().

    Returns:
        A dictionary with "capture_summary" and "conversations" keys,
        matching the expected output schema.
    """
    # Step 1: reconstruct TCP handshakes per tcp.stream and attach them to
    # each TCP packet. tcp.stream is used only for this purpose.
    handshakes = _compute_tcp_handshakes(packets)
    _attach_handshakes(packets, handshakes)

    # Step 2: group packets into IP-pair conversations.
    conversations = _build_conversations(packets)

    # Step 3: compute the global capture summary.
    capture_summary = _build_capture_summary(packets, conversation_count=len(conversations))

    return {
        "capture_summary": capture_summary,
        "conversations": conversations,
    }


if __name__ == "__main__":
    import json
    import sys

    from extractor import extract_packets

    if len(sys.argv) != 2:
        print("Usage: python aggregator.py <capture.pcap>", file=sys.stderr)
        sys.exit(1)

    extracted_packets = extract_packets(sys.argv[1])
    result = aggregate_packets(extracted_packets)
    print(json.dumps(result, indent=2))