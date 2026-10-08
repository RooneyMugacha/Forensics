> **Fictional example for format reference only. Not a real challenge or solve.**

# CTF Writeup: "Lost Memories" (Forensics — 350 pts)

**Event:** ExampleCTF 2026
**Category:** Forensics
**Points:** 350
**Files provided:** `lost_memories.zip` → contains `capture.pcapng`, `flash.img`

---

## Challenge Description

> *"Our intern plugged a mystery USB drive into the office printer and now the printer won't stop talking to a weird IP address. Figure out what happened and find the flag."*

---

## TL;DR

Flag is hidden with LSB steganography inside a PNG that was exfiltrated over DNS, after being extracted from a flash image. Full flag:

```
flag{dns_tunnels_and_steg_cant_hide_from_zsteg}
```

---

## Step 1 — Initial Triage

Unzipped the archive and checked both files:

```bash
$ file *
capture.pcapng: pcapng capture file - version 1.0
flash.img:      data
```

`flash.img` didn't resolve to anything useful with `file`, so ran `binwalk` on it next:

```bash
$ binwalk flash.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------
0             0x0             DOS executable (MZ)
512           0x200           SquashFS filesystem, little endian, version 4.0
```

So `flash.img` is firmware, not a disk image — a SquashFS filesystem starting at offset `0x200`.

---

## Step 2 — Extract the Filesystem

```bash
$ binwalk -e flash.img
$ cd _flash.img.extracted/squashfs-root
$ find . -type f
./etc/passwd
./etc/dnsmasq.conf
./usr/bin/update_agent
./var/www/html/logo.png
```

`logo.png` stood out immediately — a firmware image doesn't usually ship a random logo in `/var/www/html` unless it matters. Checked it first:

```bash
$ file logo.png
logo.png: PNG image data, 512 x 512, 8-bit/color RGBA, non-interlaced

$ exiftool logo.png
# nothing unusual in metadata
```

Metadata was clean, so tried steganography tools next:

```bash
$ zsteg logo.png
imagedata           .. text: "aGVscGZsYWd7ZG5zX3R1bm5lbHM="
```

That's base64. Decoded it:

```bash
$ echo "aGVscGZsYWd7ZG5zX3R1bm5lbHM=" | base64 -d
helpflag{dns_tunnels
```

Truncated — `zsteg`'s default LSB extraction only grabbed part of the payload. Needed the rest.

---

## Step 3 — Checking `update_agent`

Before going deeper into the image, checked the other interesting file from the extracted filesystem — a binary that might explain *how* the data left the device.

```bash
$ file usr/bin/update_agent
usr/bin/update_agent: ELF 32-bit LSB executable, ARM

$ strings usr/bin/update_agent | grep -i dns
dns_exfil_chunk: %s.data.evil-update-server.test
```

That confirmed the exfiltration channel was DNS — the binary chunks data and sends it as subdomain labels to `evil-update-server.test`. Time to check the pcap.

---

## Step 4 — Pulling the Payload from DNS Traffic

```bash
$ tshark -r capture.pcapng -Y "dns.qry.name contains \"evil-update-server.test\"" -T fields -e dns.qry.name
```

This returned ~40 queries, each a subdomain chunk:

```
yWZ7ZG5zX3R1bm5lbHM.data.evil-update-server.test
gYW5kX3N0ZWdfY2FudA.data.evil-update-server.test
X2hpZGVfZnJvbV96c3Rl.data.evil-update-server.test
Zy5kYXRhLmV2aWw.data.evil-update-server.test
...
```

Extracted just the data labels, stripped the domain suffix, and reassembled them in query order:

```bash
$ tshark -r capture.pcapng -Y "dns.qry.name contains \"evil-update-server.test\"" \
    -T fields -e frame.time_epoch -e dns.qry.name \
    | sort -n | awk '{print $2}' | sed 's/\.data\.evil-update-server\.test//' \
    | tr -d '\n' > payload.b64
```

Padded the base64 string (DNS labels strip padding characters) and decoded:

```bash
$ python3 -c "
import base64
data = open('payload.b64').read()
data += '=' * (-len(data) % 4)
print(base64.b64decode(data).decode())
"
helpflag{dns_tunnels_and_steg_cant_hide_from_zsteg}
```

That gave the full string — but it started with "help" which looked off for a flag format.

---

## Step 5 — Fixing the Off-by-One

Comparing against the partial decode from Step 2 (`zsteg`'s output), the `logo.png` LSB data and the DNS-reassembled data overlapped but were offset by 4 characters — the DNS capture had clearly missed the very first chunk (likely sent before the capture started). Used the `zsteg` output to patch the beginning:

```
zsteg (partial):        aGVscGZsYWd7ZG5zX3R1bm5lbHM=  → "helpflag{dns_tunnels"
DNS reassembly (full):  "helpflag{dns_tunnels_and_steg_cant_hide_from_zsteg}"
```

The leading `help` was actually the tail end of a sentence cut off before the real flag started (the challenge author's red herring / intro text got base64-encoded along with the flag). Stripping it down to the `flag{...}` boundary gave the final answer.

---

## Flag

```
flag{dns_tunnels_and_steg_cant_hide_from_zsteg}
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| `file`, `binwalk` | Identify and extract the firmware image |
| `exiftool` | Check PNG metadata (came back clean) |
| `zsteg` | Find LSB-encoded data in the PNG |
| `strings` | Find the C2 domain inside the extracted binary |
| `tshark` | Filter and extract DNS query data from the pcap |
| `python3` / `base64` | Reassemble and decode the exfiltrated payload |

## Lessons / Notes for Next Time

- Always run `binwalk` on anything `file` can't identify — firmware blobs rarely look like anything on their own.
- Check **every** extracted file from a firmware dump, not just the ones that look obviously interesting — the binary (`update_agent`) was the key to understanding *why* to look at the pcap at all.
- `zsteg`'s default settings don't always grab a full payload; worth re-running with `-a` (try all methods) if the output looks truncated.
- DNS exfiltration challenges are solved by sorting the captured queries by **time**, not by the order Wireshark lists them if filters are applied oddly — always sort on `frame.time_epoch` before reassembling.
