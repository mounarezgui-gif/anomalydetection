"""
extractor.py
============

Extracts per-packet information from a PCAP file using a single TShark
invocation (subprocess). No PyShark, no Scapy.

The module performs exactly ONE read of the capture file. TShark is asked
to emit a fixed set of fields in TSV form on stdout, which is parsed line
by line (streaming) to keep memory usage proportional to the number of
packets rather than to the size of TShark's raw output buffer.

Output: a list of dictionaries, one per packet, ready to be consumed by
aggregator.py.

Compatible with Python 3.11+.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Final, Iterator, Optional


class PacketExtractionError(Exception):
    """Raised when TShark is unavailable or fails to read a PCAP file."""


# Fallback locations checked when "tshark" is not found on PATH. Wireshark's
# Windows installer does not add itself to PATH by default, so we also look
# in its usual install directories before giving up.
_TSHARK_FALLBACK_PATHS: Final[list[str]] = [
    # Windows
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    # macOS (Wireshark.app bundle, and common Homebrew locations)
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    # Linux
    "/usr/bin/tshark",
]

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Fields requested from TShark, in the exact order they will appear in the
# TSV output. Keep this list and _parse_fields_line() in sync.
TSHARK_FIELDS: Final[list[str]] = [
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.stream",
    "dhcp.option.dhcp",   # <- nouveau : type de message DHCP (1=DISCOVER...8=INFORM)
    "eth.src",             # <- nouveau : MAC source, pour distinguer les clients
]

# Standard / well-known ports for the application protocols we detect.
# Used to compute the "default_port" boolean.
DEFAULT_PORTS: Final[dict[str, set[int]]] = {
    "HTTP": {80},
    "HTTPS": {443},
    "QUIC": {443},
    "DNS": {53},
    "DHCP": {67, 68},
    "SSH": {22},
    "FTP": {20, 21},
}

# TCP flag bitmasks (as used in the tcp.flags 16-bit field).
TCP_FLAG_FIN: Final[int] = 0x0001
TCP_FLAG_SYN: Final[int] = 0x0002
TCP_FLAG_RST: Final[int] = 0x0004
TCP_FLAG_ACK: Final[int] = 0x0010

# Segments of frame.protocols that are transport/network layers only, not
# an application protocol. If the highest (last) layer in the stack is one
# of these, it means TShark did not recognize any application protocol on
# top of it, so we fall back to the transport-layer protocol (TCP/UDP).
_TRANSPORT_ONLY_LAYERS: Final[set[str]] = {
    "eth", "ethertype", "ip", "ipv6", "tcp", "udp", "data", "vlan",
}

# Optional renaming for TShark's raw layer names, so the output stays
# consistent with names used elsewhere in the pipeline (HTTPS instead of
# TLS/SSL, HTTP instead of HTTP2, etc.). Anything not listed here just
# gets its TShark name uppercased (e.g. "quic" -> "QUIC", "ntp" -> "NTP").
_PROTOCOL_NAME_OVERRIDES: Final[dict[str, str]] = {
    "http2": "HTTP",
    "http": "HTTP",
    "tls": "HTTPS",
    "ssl": "HTTPS",
    "bootp": "DHCP",
    "ftp-data": "FTP",
    "icmpv6": "ICMP",
}

DHCP_MESSAGE_TYPES: Final[dict[int, str]] = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}
# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _safe_int(value: str) -> Optional[int]:
    """Convert a TShark field value to int, returning None on failure."""
    if not value:
        return None
    try:
        # Some fields (e.g. tcp.srcport) can rarely contain a comma-joined
        # list when a field repeats; take the first occurrence defensively.
        first = value.split(",")[0].strip()
        return int(first)
    except (ValueError, AttributeError):
        return None


def _safe_float(value: str) -> Optional[float]:
    """Convert a TShark field value to float, returning None on failure."""
    if not value:
        return None
    try:
        return float(value.split(",")[0].strip())
    except (ValueError, AttributeError):
        return None


def _safe_str(value: str) -> Optional[str]:
    """Return a stripped string, or None if the field is empty."""
    if not value:
        return None
    cleaned = value.split(",")[0].strip()
    return cleaned or None


def _parse_tcp_flags(raw_flags: str) -> int:
    """Parse a tcp.flags hex string (e.g. '0x00000018') into an int mask."""
    if not raw_flags:
        return 0
    token = raw_flags.split(",")[0].strip()
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return 0


def _detect_protocol(frame_protocols: Optional[str], transport: Optional[str]) -> str:
    """
    Determine the application-layer protocol from the last layer in the
    frame.protocols stack (e.g. "eth:ethertype:ip:udp:quic" -> "QUIC").

    Falls back to the transport-layer protocol (TCP/UDP) when the highest
    layer found is itself transport/network-only (no app protocol was
    recognized by TShark), and to "UNKNOWN" when nothing could be
    determined at all.
    """
    if frame_protocols:
        layers = frame_protocols.lower().split(":")
        if layers:
            highest = layers[-1].strip()
            if highest and highest not in _TRANSPORT_ONLY_LAYERS:
                return _PROTOCOL_NAME_OVERRIDES.get(highest, highest.upper())

    if transport:
        return transport

    return "UNKNOWN"


def _is_default_port(protocol: str, src_port: Optional[int], dst_port: Optional[int]) -> bool:
    """Return True if either port matches the well-known port(s) for the protocol."""
    standard_ports = DEFAULT_PORTS.get(protocol)
    if not standard_ports:
        return False
    return (src_port in standard_ports) or (dst_port in standard_ports)


@dataclass(frozen=True)
class _RawFields:
    """Container mirroring one TShark TSV output line, before typing."""

    frame_number: str
    time_epoch: str
    time_relative: str
    frame_len: str
    frame_protocols: str
    ip_src: str
    ip_dst: str
    tcp_srcport: str
    tcp_dstport: str
    udp_srcport: str
    udp_dstport: str
    tcp_flags: str
    tcp_stream: str
    dhcp_type: str      # <- nouveau
    eth_src: str        # <- nouveau


def _split_line(line: str) -> Optional[_RawFields]:
    """Split one TSV line from TShark into a _RawFields tuple."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(TSHARK_FIELDS):
        # Pad missing trailing columns instead of raising: TShark omits
        # trailing empty fields in some versions.
        parts = parts + [""] * (len(TSHARK_FIELDS) - len(parts))
    try:
        return _RawFields(*parts[: len(TSHARK_FIELDS)])
    except TypeError:
        # Malformed line (too many/few fields after padding): skip safely.
        return None


# --------------------------------------------------------------------------
# TShark invocation
# --------------------------------------------------------------------------


def _find_tshark_executable() -> str:
    """
    Locate the tshark executable, trying in order:
      1. PATH (shutil.which)
      2. the TSHARK_PATH environment variable, if set
      3. common OS-specific default installation directories

    Raises:
        PacketExtractionError: if tshark cannot be found anywhere.
    """
    on_path = shutil.which("tshark")
    if on_path:
        return on_path

    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    for candidate in _TSHARK_FALLBACK_PATHS:
        if os.path.isfile(candidate):
            return candidate

    raise PacketExtractionError(
        "tshark executable not found. Install Wireshark/TShark, make sure "
        "it is on your PATH, or set the TSHARK_PATH environment variable "
        "to the full path of tshark(.exe)."
    )


def _build_tshark_command(pcap_path: str) -> list[str]:
    """Build the single TShark command line used to extract every field."""
    tshark_bin = _find_tshark_executable()

    command: list[str] = [
        tshark_bin,
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "occurrence=f",   # keep only the first occurrence per field
        "-E", "quote=n",
    ]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])
    return command


def _iter_tshark_lines(pcap_path: str) -> Iterator[str]:
    """
    Run TShark once and yield its stdout lines lazily.

    Using Popen + iterating over stdout avoids buffering the entire
    (potentially huge) output in memory at once.
    """
    command = _build_tshark_command(pcap_path)

    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    ) as process:
        assert process.stdout is not None
        for line in process.stdout:
            if line.strip():
                yield line

        stderr_output = process.stderr.read() if process.stderr else ""
        return_code = process.wait()

        if return_code != 0:
            raise PacketExtractionError(
                f"TShark exited with code {return_code} while processing "
                f"'{pcap_path}': {stderr_output.strip()}"
            )


# --------------------------------------------------------------------------
# Packet parsing
# --------------------------------------------------------------------------


def _build_packet(raw: _RawFields) -> Optional[dict]:
    """Convert one _RawFields record into the final packet dictionary."""
    frame_number = _safe_int(raw.frame_number)
    if frame_number is None:
        # A packet without a frame number is unusable; skip it defensively.
        return None

    time_epoch = _safe_float(raw.time_epoch)
    time_relative = _safe_float(raw.time_relative)
    length_bytes = _safe_int(raw.frame_len) or 0
    frame_protocols = _safe_str(raw.frame_protocols)

    src_ip = _safe_str(raw.ip_src)
    dst_ip = _safe_str(raw.ip_dst)

    tcp_src = _safe_int(raw.tcp_srcport)
    tcp_dst = _safe_int(raw.tcp_dstport)
    udp_src = _safe_int(raw.udp_srcport)
    udp_dst = _safe_int(raw.udp_dstport)

    is_tcp = tcp_src is not None or tcp_dst is not None
    is_udp = udp_src is not None or udp_dst is not None

    src_port = tcp_src if is_tcp else udp_src
    dst_port = tcp_dst if is_tcp else udp_dst

    transport = "TCP" if is_tcp else ("UDP" if is_udp else None)
    protocol = _detect_protocol(frame_protocols, transport)
    default_port = _is_default_port(protocol, src_port, dst_port)

    tcp_info: Optional[dict] = None
    if is_tcp:
        flags_mask = _parse_tcp_flags(raw.tcp_flags)
        tcp_stream = _safe_int(raw.tcp_stream)
        tcp_info = {
            "stream": tcp_stream,
            "syn": bool(flags_mask & TCP_FLAG_SYN),
            "ack": bool(flags_mask & TCP_FLAG_ACK),
            "fin": bool(flags_mask & TCP_FLAG_FIN),
            "rst": bool(flags_mask & TCP_FLAG_RST),
            # "handshake" is deliberately left out here: it requires a
            # cross-packet view of the whole tcp.stream and is computed
            # later by aggregator.py.
        }
    dhcp_type_code = _safe_int(raw.dhcp_type)
    dhcp_message_type = DHCP_MESSAGE_TYPES.get(dhcp_type_code) if dhcp_type_code is not None else None
    client_mac = _safe_str(raw.eth_src)
    return {
        "packet_number": frame_number,
        "timestamp": time_epoch,
        "relative_time": time_relative,
        "frame_protocols": frame_protocols,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length_bytes": length_bytes,
        "length_bits": length_bytes * 8,
        "default_port": default_port,
        "dhcp_message_type": dhcp_message_type,   # <- nouveau
        "client_mac": client_mac,                  # <- nouveau
        "tcp": tcp_info,
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def extract_packets(pcap_path: str) -> list[dict]:
    """
    Extract all packets from a PCAP file using a single TShark run.

    Args:
        pcap_path: Path to the .pcap / .pcapng file.

    Returns:
        A list of packet dictionaries (see module docstring for schema).

    Raises:
        PacketExtractionError: if tshark is not installed, or if it fails
            while reading the given file.
    """
    packets: list[dict] = []

    for line in _iter_tshark_lines(pcap_path):
        raw = _split_line(line)
        if raw is None:
            continue

        packet = _build_packet(raw)
        if packet is not None:
            packets.append(packet)

    return packets


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python extractor.py <capture.pcap>", file=sys.stderr)
        sys.exit(1)

    extracted_packets = extract_packets(sys.argv[1])
    print(json.dumps(extracted_packets, indent=2))