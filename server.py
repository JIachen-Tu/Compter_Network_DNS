"""UDP DNS server entry point."""
import argparse
import socket
from cache import DNSCache
from dns_message import parse_message, make_client_response, build_error_response
from resolver import IterativeResolver, ResolutionError

RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NOTIMP = 4


def main():
    parser = argparse.ArgumentParser(description="Iterative IPv4 DNS resolver")
    parser.add_argument("port", nargs="?", type=int, default=53)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    cache = DNSCache()
    resolver = IterativeResolver(timeout=args.timeout)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", args.port))
    print(f"DNS resolver listening on UDP 0.0.0.0:{args.port}", flush=True)

    while True:
        packet, client = server.recvfrom(65535)
        try:
            request = parse_message(packet)
            if request.flags & 0x8000:
                continue  
            if ((request.flags >> 11) & 0xF) != 0:
                server.sendto(build_error_response(request, RCODE_NOTIMP), client)
                continue
            if len(request.questions) != 1:
                server.sendto(build_error_response(request, RCODE_FORMERR), client)
                continue

            question = request.questions[0]
            cached = cache.get(question.name, question.qtype, question.qclass)
            if cached is not None:
                from dns_message import build_cached_response
                response = build_cached_response(request, cached)
            else:
                try:
                    answers = resolver.resolve(question.name, question.qtype,
                                               question.qclass)
                    if answers:
                        cache.put_records(answers)
                    from dns_message import build_answer_response
                    response = build_answer_response(request, answers)
                except ResolutionError as exc:
                    print(f"Resolution failed for {question.name}: {exc}", flush=True)
                    response = build_error_response(request, getattr(exc, "rcode", RCODE_SERVFAIL))
            server.sendto(response, client)
        except (ValueError, UnicodeDecodeError, struct.error) as exc:
            print(f"Dropped malformed packet from {client}: {exc}", flush=True)
        except Exception as exc:
            print(f"Unexpected error for {client}: {exc}", flush=True)


if __name__ == "__main__":
    import struct
    main()
