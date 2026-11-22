"""DNS wire-format helpers. Standard library only; no DNS package is used."""
from __future__ import annotations
import ipaddress
import random
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

HEADER_SIZE = 12
TYPE_NAMES = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA",
    7: "MB", 8: "MG", 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR",
    13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT",
}
CLASS_NAMES = {1: "IN"}


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int
    wire: bytes


@dataclass
class ResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    rdata_offset: int
    raw: bytes
    parsed: object = None


@dataclass
class DNSMessage:
    ident: int
    flags: int
    questions: List[Question]
    answers: List[ResourceRecord]
    authorities: List[ResourceRecord]
    additionals: List[ResourceRecord]
    raw: bytes

    @property
    def rcode(self):
        return self.flags & 0x000F

    @property
    def is_truncated(self):
        return bool(self.flags & 0x0200)


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    total = 1
    for label in name.split("."):
        try:
            b = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("Domain labels must be ASCII/punycode") from exc
        if not b or len(b) > 63:
            raise ValueError("Each DNS label must contain 1..63 bytes")
        total += 1 + len(b)
        if total > 255:
            raise ValueError("DNS name exceeds 255 wire bytes")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def decode_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Decode a possibly compressed name; return (name, bytes_consumed_at_offset)."""
    labels = []
    pos = offset
    consumed = None
    visited = set()
    wire_length = 1
    while True:
        if pos >= len(packet):
            raise ValueError("Name extends beyond packet")
        length = packet[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if pointer >= len(packet):
                raise ValueError("Compression pointer outside packet")
            if pointer in visited:
                raise ValueError("Compression pointer loop")
            visited.add(pointer)
            if len(visited) > 128:
                raise ValueError("Excessive compression pointer chain")
            if consumed is None:
                consumed = pos + 2 - offset
            pos = pointer
            continue
        if length & 0xC0:
            raise ValueError("Unsupported DNS label encoding")
        pos += 1
        if length == 0:
            if consumed is None:
                consumed = pos - offset
            break
        if length > 63 or pos + length > len(packet):
            raise ValueError("Invalid or truncated DNS label")
        label = packet[pos:pos + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("Non-ASCII label in DNS packet") from exc
        wire_length += 1 + length
        if wire_length > 255:
            raise ValueError("DNS name exceeds 255 wire bytes")
        pos += length
    return ".".join(labels), consumed


def _parse_rdata(packet: bytes, rrtype: int, start: int, rdlength: int):
    end = start + rdlength
    if end > len(packet):
        raise ValueError("RDATA extends beyond packet")
    data = packet[start:end]
    if rrtype in (2, 5, 12):  
        name, used = decode_name(packet, start)
        if used != rdlength:
            raise ValueError("Unexpected trailing bytes in domain-name RDATA")
        return name
    if rrtype == 15:  
        if rdlength < 3:
            raise ValueError("Invalid MX RDATA")
        preference = struct.unpack("!H", data[:2])[0]
        exchange, used = decode_name(packet, start + 2)
        if used + 2 != rdlength:
            raise ValueError("Invalid MX exchange name")
        return (preference, exchange)
    if rrtype == 1 and rdlength == 4:
        return str(ipaddress.IPv4Address(data))
    return data


def parse_message(packet: bytes) -> DNSMessage:
    if len(packet) < HEADER_SIZE:
        raise ValueError("DNS packet shorter than 12-byte header")
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    pos = HEADER_SIZE
    questions = []
    for _ in range(qd):
        start = pos
        name, used = decode_name(packet, pos)
        pos += used
        if pos + 4 > len(packet):
            raise ValueError("Truncated question")
        qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
        pos += 4
        questions.append(Question(name, qtype, qclass, packet[start:pos]))

    def read_rr():
        nonlocal pos
        start = pos
        name, used = decode_name(packet, pos)
        pos += used
        if pos + 10 > len(packet):
            raise ValueError("Truncated resource-record header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[pos:pos + 10])
        pos += 10
        rdata_offset = pos
        if pos + rdlength > len(packet):
            raise ValueError("Truncated resource-record RDATA")
        parsed = _parse_rdata(packet, rtype, pos, rdlength)
        pos += rdlength
        return ResourceRecord(name, rtype, rclass, ttl,
                              packet[rdata_offset:pos], rdata_offset,
                              packet[start:pos], parsed)

    answers = [read_rr() for _ in range(an)]
    authorities = [read_rr() for _ in range(ns)]
    additionals = [read_rr() for _ in range(ar)]
    if pos != len(packet):
        raise ValueError("Unexpected trailing bytes after DNS sections")
    return DNSMessage(ident, flags, questions, answers, authorities, additionals, packet)


EDNS_UDP_PAYLOAD_SIZE = 4096


def build_opt_record(udp_payload_size: int = EDNS_UDP_PAYLOAD_SIZE) -> bytes:
    """Build the assignment's basic EDNS(0) OPT pseudo-RR (empty RDATA)."""
    if not 512 <= udp_payload_size <= 65535:
        raise ValueError("EDNS UDP payload size must be between 512 and 65535")
    return b"\x00" + struct.pack("!HHIH", 41, udp_payload_size, 0, 0)


def build_query(name: str, qtype: int, qclass: int = 1,
                ident: Optional[int] = None,
                use_edns: bool = True) -> bytes:
    if ident is None:
        ident = random.randrange(0, 65536)
    flags = 0  
    question = encode_name(name) + struct.pack("!HH", qtype, qclass)
    opt = build_opt_record() if use_edns else b""
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 1 if use_edns else 0)
    return header + question + opt


def make_client_response(upstream_packet: bytes, client_id: int,
                         client_flags: int) -> bytes:
    msg = parse_message(upstream_packet)
    flags = (msg.flags & 0x87F0) | 0x8000 | (client_flags & 0x7900) | 0x0080
    return struct.pack("!HH", client_id, flags) + upstream_packet[4:]


def build_error_response(query: DNSMessage, rcode: int) -> bytes:
    q = query.questions
    flags = 0x8000 | 0x0080 | (query.flags & 0x7900) | (rcode & 0xF)
    question_wire = b"".join(x.wire for x in q)
    header = struct.pack("!HHHHHH", query.ident, flags, len(q), 0, 0, 0)
    return header + question_wire


def _pack_rr(rr: ResourceRecord) -> bytes:
    owner = encode_name(rr.name)
    if rr.rtype in (2, 5, 12) and isinstance(rr.parsed, str):
        rdata = encode_name(rr.parsed)
    elif rr.rtype == 15 and isinstance(rr.parsed, tuple):
        rdata = struct.pack("!H", rr.parsed[0]) + encode_name(rr.parsed[1])
    else:
        rdata = rr.rdata
    return (owner + struct.pack("!HHIH", rr.rtype, rr.rclass,
                                max(0, rr.ttl), len(rdata)) + rdata)


def build_answer_response(request: DNSMessage, answers) -> bytes:
    question_wire = b"".join(q.wire for q in request.questions)
    packed = b"".join(_pack_rr(rr) for rr in answers)
    client_opt = next((rr for rr in request.additionals if rr.rtype == 41), None)
    opt_wire = build_opt_record(client_opt.rclass) if client_opt else b""
    flags = 0x8000 | 0x0080 | (request.flags & 0x7900)
    header = struct.pack("!HHHHHH", request.ident, flags,
                         len(request.questions), len(answers), 0,
                         1 if client_opt else 0)
    return header + question_wire + packed + opt_wire


def build_cached_response(request: DNSMessage, answers) -> bytes:
    return build_answer_response(request, answers)
