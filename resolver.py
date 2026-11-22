"""Iterative IPv4 DNS resolver. Uses UDP and no third-party DNS libraries."""
import random
import socket

from dns_message import build_query, parse_message
from root_servers import ROOT_SERVERS


class ResolutionError(Exception):
    def __init__(self, message, rcode=2):
        super().__init__(message)
        self.rcode = rcode


class IterativeResolver:
    def __init__(self, timeout=3.0, max_steps=40, max_cname=12):
        self.timeout = timeout
        self.max_steps = max_steps
        self.max_cname = max_cname

    def _query(self, server_ip, name, qtype, qclass):
        query = build_query(name, qtype, qclass)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(query, (server_ip, 53))
            packet, peer = sock.recvfrom(65535)
        except OSError as exc:
            raise ResolutionError(
                f"UDP query to {server_ip} failed: {exc}"
            ) from exc
        finally:
            sock.close()

        msg = parse_message(packet)
        if peer[0] != server_ip:
            raise ResolutionError("Response from unexpected DNS server")
        if msg.ident != int.from_bytes(query[:2], "big"):
            raise ResolutionError("Transaction ID mismatch")
        if not (msg.flags & 0x8000):
            raise ResolutionError("Upstream packet is not a DNS response")
        if len(msg.questions) != 1:
            raise ResolutionError("Unexpected number of questions")
        question = msg.questions[0]
        if (
            question.name.rstrip(".").lower() != name.rstrip(".").lower()
            or question.qtype != qtype
            or question.qclass != qclass
        ):
            raise ResolutionError("DNS question mismatch")
        if msg.rcode != 0:
            raise ResolutionError(
                f"Upstream DNS returned RCODE={msg.rcode}",
                rcode=msg.rcode,
            )
        if msg.is_truncated:
            raise ResolutionError(
                "Truncated UDP response; TCP fallback is not implemented"
            )
        return msg

    @staticmethod
    def _is_suffix(name, suffix):
        n = name.rstrip(".").lower()
        s = suffix.rstrip(".").lower()
        return n == s or n.endswith("." + s) or s == ""

    def _referral(self, msg, qname):
        ns_records = [
            rr for rr in msg.authorities
            if rr.rtype == 2
            and isinstance(rr.parsed, str)
            and self._is_suffix(qname, rr.name)
        ]
        if not ns_records:
            return None, [], set()

        longest = max(len(rr.name) for rr in ns_records)
        ns_records = [rr for rr in ns_records if len(rr.name) == longest]
        targets = [rr.parsed for rr in ns_records]

        glue = []
        glued_names = set()
        target_set = {target.lower() for target in targets}
        for rr in msg.additionals:
            if (rr.rtype == 1 and rr.rclass == 1
                    and rr.name.lower() in target_set
                    and isinstance(rr.parsed, str)):
                glue.append(rr.parsed)
                glued_names.add(rr.name.lower())

        return targets, glue, glued_names

    @staticmethod
    def _is_authoritative_nodata(msg):
        """True for an authoritative NOERROR response with no requested RRset.

        An SOA in the authority section identifies a negative (NODATA) answer.
        This is a valid DNS result, not a resolution failure.
        """
        is_authoritative = bool(msg.flags & 0x0400)  # AA bit
        has_soa = any(rr.rtype == 6 for rr in msg.authorities)
        return is_authoritative and not msg.answers and has_soa

    def _resolve_ns_address(self, ns_name, depth=0):
        if depth > 5:
            raise ResolutionError("Nameserver-address resolution recursion limit")

        answers = self.resolve(
            ns_name, 1, 1, allow_cache=False, depth=depth + 1
        )
        return [
            rr.parsed for rr in answers
            if rr.rtype == 1 and isinstance(rr.parsed, str)
        ]

    def resolve(self, qname, qtype, qclass=1, allow_cache=True, depth=0):
        if depth > 5:
            raise ResolutionError("Nested resolution limit")

        current_name = qname.rstrip(".")
        all_answers = []
        cname_seen = {current_name.lower()}

        for cname_hop in range(self.max_cname + 1):
            servers = list(ROOT_SERVERS)
            visited = set()
            final_answers = None

            for _ in range(self.max_steps):
                if not servers:
                    raise ResolutionError(
                        f"No nameserver IPs available for {current_name}"
                    )

            
                server_ip = servers.pop(0)
                state = (
                    server_ip,
                    current_name.lower(),
                    qtype,
                    qclass,
                )
                if state in visited:
                    continue
                visited.add(state)

                try:
                    msg = self._query(
                        server_ip, current_name, qtype, qclass
                    )
                except ResolutionError as exc:
                    if exc.rcode != 2:
                        raise
                    continue
                except ValueError:
                    continue

                direct = [
                    rr for rr in msg.answers
                    if rr.rclass == qclass
                    and (
                        rr.name.lower() == current_name.lower()
                        or rr.rtype == 5
                    )
                ]
                if direct:
                    final_answers = direct
                    break

                targets, glue, glued_names = self._referral(msg, current_name)
                if targets is not None:

                    next_ips = list(glue)
                    for target in targets:
                        if target.lower() in glued_names:
                            continue
                        try:
                            next_ips.extend(
                                self._resolve_ns_address(target, depth)
                            )
                        except ResolutionError:
                            continue
                    if next_ips:
                        servers = list(dict.fromkeys(next_ips))
                        continue

                
                if self._is_authoritative_nodata(msg):
                    final_answers = []
                    break


            if final_answers is None:
                raise ResolutionError(
                    f"Could not resolve {current_name} "
                    "(no usable answer/referral)"
                )

            all_answers.extend(final_answers)
            cname_rr = next(
                (
                    rr for rr in final_answers
                    if rr.rtype == 5 and isinstance(rr.parsed, str)
                ),
                None,
            )
            if cname_rr is None or qtype == 5:
                return all_answers

            target = cname_rr.parsed
            if target.lower() in cname_seen:
                raise ResolutionError("CNAME loop detected")
            cname_seen.add(target.lower())
            current_name = target

        raise ResolutionError("Too many CNAME redirects")
