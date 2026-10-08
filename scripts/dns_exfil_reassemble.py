#!/usr/bin/env python3
"""Reassemble base64 data exfiltrated in DNS query subdomains.

Usage:
    tshark -r capture.pcap -Y 'dns.qry.name contains "example.test"' \
        -T fields -e frame.time_epoch -e dns.qry.name > queries.tsv
    python3 dns_exfil_reassemble.py queries.tsv example.test
"""
import base64
import sys


def main(path, domain):
    rows = []
    with open(path) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) != 2:
                continue
            ts, name = parts
            if not name.endswith(domain):
                continue
            label = name[: -len(domain)].rstrip(".")
            # keep only the first label (the data chunk); adjust if the format differs
            rows.append((float(ts), label.split(".")[0]))

    rows.sort()  # order by time
    seen, chunks = set(), []
    for _, chunk in rows:
        if chunk not in seen:  # drop retransmitted duplicates
            seen.add(chunk)
            chunks.append(chunk)

    data = "".join(chunks)
    data += "=" * (-len(data) % 4)
    try:
        sys.stdout.buffer.write(base64.b64decode(data))
    except Exception as e:
        sys.exit(f"decode failed: {e}\nraw data: {data}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
