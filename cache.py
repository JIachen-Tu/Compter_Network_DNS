"""In-memory DNS RR cache with per-record TTL expiration."""
import time
from dataclasses import replace


class DNSCache:
    def __init__(self):
        self._entries = {}

    @staticmethod
    def _key(name, qtype, qclass):
        return (name.rstrip(".").lower(), int(qtype), int(qclass))

    def get(self, name, qtype, qclass):
        key = self._key(name, qtype, qclass)
        now = time.monotonic()
        entries = self._entries.get(key)
        if entries is None:
            return None
        live = [(rr, expires) for rr, expires in entries if expires > now]
        if not live:
            self._entries.pop(key, None)
            return None
        self._entries[key] = live
        return [replace(rr, ttl=max(0, int(expires - now))) for rr, expires in live]

    def put_records(self, records):
        now = time.monotonic()
        grouped = {}
        for rr in records:
            if rr.ttl <= 0:
                continue
            key = self._key(rr.name, rr.rtype, rr.rclass)
            grouped.setdefault(key, []).append((rr, now + rr.ttl))
        self._entries.update(grouped)

    def clear(self):
        self._entries.clear()

    def __len__(self):
        return len(self._entries)
