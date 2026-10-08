# The Digital Forensics Toolkit: A Complete Reference

A field guide to the tools used across disk, memory, network, mobile, and firmware forensics — what each one does, when to reach for it, and the commands to get started.

---

## 1. Acquisition & Imaging

Getting a forensically sound copy of the evidence, before any analysis happens.

### `dd` / `dc3dd` / `dcfldd`
Bit-for-bit copiers. `dc3dd` and `dcfldd` are forensic forks of `dd` that add hashing and progress output.
```bash
dc3dd if=/dev/sdb of=evidence.dd hash=sha256 log=acquire.log
dcfldd if=/dev/sdb of=evidence.dd hash=sha256,md5 hashlog=hash.log
```

### FTK Imager (AccessData)
Free GUI tool for imaging drives, mounting images, and previewing files without altering timestamps. Produces `.E01`, `.AD1`, or raw formats. Standard first tool in many Windows-based labs.

### `ewfacquire` / `ewfinfo` / `ewfmount` (libewf)
Create, inspect, and mount EWF/E01 images (the Expert Witness Format used by EnCase/FTK).
```bash
ewfacquire /dev/sdb          # interactive acquisition to .E01
ewfinfo evidence.E01         # metadata: hash, acquisition date, examiner notes
ewfmount evidence.E01 /mnt/ewf   # exposes raw image at /mnt/ewf/ewf1
```

### Guymager
Linux GUI imaging tool, similar role to FTK Imager, outputs `.E01`/`.dd`, computes hashes during acquisition.

### `simg2img`
Converts Android sparse images (common in flash dumps) to raw images you can mount or parse.
```bash
simg2img sparse.img raw.img
```

### Write blockers (Tableau, CRU WiebeTech)
Hardware devices that physically prevent write commands from reaching the source drive during acquisition. Not software, but essential for chain-of-custody-grade work.

---

## 2. File & Data Identification

### `file`
Identifies file type from magic bytes, regardless of extension.
```bash
file suspicious.bin
```

### `xxd` / `hexdump` / `HxD` / `ImHex`
Hex viewers/editors. `xxd`/`hexdump` are CLI; HxD (Windows) and ImHex (cross-platform, has a pattern-language for parsing binary structures) are GUI.
```bash
xxd image.jpg | head
xxd -s 0x100 -l 64 file.bin   # view 64 bytes starting at offset 0x100
```

### `binwalk`
Scans a binary blob for embedded file signatures, compressed data, and filesystems — the go-to tool for firmware and appended-data analysis.
```bash
binwalk firmware.bin          # scan and list findings
binwalk -e firmware.bin       # scan and extract
binwalk -Me firmware.bin      # recursive extraction
binwalk -E firmware.bin       # entropy graph (find encryption/compression)
```

### `unblob`
Modern, more robust alternative to binwalk for recursive extraction of nested/embedded files and firmware.
```bash
unblob firmware.bin
```

### TrID
Identifies file type by matching against a large signature database, useful when `file` returns "data".

---

## 3. Metadata Extraction

### ExifTool
The standard tool for reading (and writing/stripping) metadata from images, documents, video, and audio.
```bash
exiftool image.jpg
exiftool -gps* image.jpg              # just GPS fields
exiftool -b -ThumbnailImage image.jpg > thumb.jpg   # extract embedded thumbnail
exiftool -all= image.jpg              # strip all metadata (for testing/redaction)
```

### `mediainfo`
Deep technical metadata for audio/video containers and codecs — useful for verifying whether a video file matches its claimed source device or software.

---

## 4. Disk & Filesystem Analysis

### The Sleuth Kit (TSK)
A command-line suite that is the backbone of most disk forensics work.
```bash
mmls disk.dd                 # list partitions and their offsets
fsstat -o <offset> disk.dd   # filesystem type and details
fls -r -o <offset> disk.dd   # recursive file listing, shows deleted files (*)
fls -r -m / -o <offset> disk.dd > bodyfile.txt   # timeline-ready listing
icat -o <offset> disk.dd <inode> > out.file      # extract file content by inode
istat -o <offset> disk.dd <inode>                # metadata/timestamps for an inode
blkls -o <offset> disk.dd    # extract unallocated blocks
blkcat -o <offset> disk.dd <block>   # dump a specific block
```

### Autopsy
The GUI front end for The Sleuth Kit. Ingest modules automatically run hash lookups, keyword search, EXIF extraction, web artifact parsing, and deleted-file recovery. Best entry point for beginners doing full-image review.

### `mount` (loopback, read-only)
Quick way to browse a partition as a normal filesystem — but shows only what a live OS would show, not deleted files or slack space.
```bash
sudo mount -o ro,loop,noexec,offset=$((512*2048)) disk.dd /mnt/evidence
```

---

## 5. Timeline Analysis

### `mactime` (part of TSK)
Turns a bodyfile into a human-readable MACB (Modified/Accessed/Changed/Born) timeline.
```bash
mactime -b bodyfile.txt -d > timeline.csv
```

### Plaso / `log2timeline.py` / `psort.py`
Builds a "super timeline" pulling from filesystem metadata, registry, event logs, browser history, and more into one sortable timeline — the industry standard for large-scale timeline work.
```bash
log2timeline.py plaso.dump disk.dd
psort.py -o dynamic plaso.dump -w timeline.csv
psort.py -o dynamic plaso.dump "date > '2024-01-01' AND date < '2024-02-01'"
```

### Timeline Explorer (Eric Zimmerman)
Windows GUI for filtering, coloring, and pivoting huge CSV timelines produced by Plaso or the EZ tools below.

---

## 6. Windows Artifact Parsers (Eric Zimmerman's Tools)

A well-known free toolset, each targeting one artifact:

| Tool | Parses |
|---|---|
| `MFTECmd` | `$MFT`, `$J` (USN journal), `$LogFile` — file creation/rename/delete history |
| `RECmd` / `RegRipper` | Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) |
| `PECmd` | Prefetch files — programs executed and when |
| `AmcacheParser` / `AppCompatCacheParser` | Amcache/Shimcache — evidence of execution |
| `LECmd` | LNK files — recently opened files, including from removable media |
| `JLECmd` | Jump Lists |
| `SBECmd` | Shellbags — folder access history |
| `SrumECmd` | System Resource Usage Monitor — app usage, network data per app |

```bash
MFTECmd.exe -f "$MFT" --csv out/
RECmd.exe --bn BatchExamples\DFIRBatch.reb -f NTUSER.DAT --csv out/
PECmd.exe -d C:\Windows\Prefetch --csv out/
```

### Chainsaw / Hayabusa
Fast command-line tools for hunting through Windows Event Logs (`.evtx`) using pre-built detection rules (Sigma-compatible). Good for quickly triaging thousands of logon/process-creation events.
```bash
chainsaw hunt evtx_dump/ -s sigma_rules/ --csv -o results/
```

---

## 7. File Carving & Deleted-File Recovery

### PhotoRec
File carver that recovers files from raw data by signature, regardless of filesystem damage. Very effective on FAT/exFAT flash media.
```bash
photorec disk.dd
```

### Foremost / Scalpel
Signature-based carvers configured via a rules file specifying header/footer patterns per file type.
```bash
foremost -t jpg,pdf,docx -i disk.dd -o carved/
scalpel disk.dd -o carved/
```

### `bulk_extractor`
Scans raw data for structured patterns — emails, URLs, credit-card-like numbers, EXIF data — without needing to understand the filesystem at all. Excellent first pass on a large, unfamiliar image.
```bash
bulk_extractor -o output_dir/ disk.dd
```

---

## 8. Firmware & Embedded Filesystems

### `unsquashfs` / `sasquatch`
Extracts SquashFS filesystems, common in router/IoT firmware. `sasquatch` handles vendor-modified/non-standard SquashFS variants that trip up the standard tool.
```bash
unsquashfs -d out/ root.squashfs
```

### `jefferson`
Extracts JFFS2 filesystem images.
```bash
jefferson firmware.jffs2 -d out/
```

### `ubireader_extract_files` / `ubireader_extract_images`
Extracts files or sub-images from UBI/UBIFS flash filesystem dumps.

### Firmware Mod Kit (FMK)
Older but still-used toolkit bundling extraction and repacking scripts for common router firmware formats.

### FirmAE / Firmadyne
Emulates extracted Linux-based firmware in QEMU so you can interact with it (web interface, services) as if it were the real device — useful for dynamic analysis and vulnerability testing.

---

## 9. Memory Forensics

### Volatility 3 (and legacy Volatility 2)
The standard framework for analyzing RAM dumps: process lists, network connections, injected code, loaded DLLs, registry data cached in memory, and more.
```bash
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.malfind      # find injected/hidden code
vol -f memory.dmp windows.dumpfiles --pid 1234
```

### Rekall
An alternative memory forensics framework, less commonly used today but still relevant for some legacy cases.

---

## 10. Network Forensics

### Wireshark / `tshark`
Packet capture analysis — protocol dissection, stream reassembly, filtering.
```bash
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap --export-objects http,extracted/
```

### `tcpdump`
Lightweight packet capture from the command line, often used to generate the `.pcap` that Wireshark later analyzes.
```bash
tcpdump -i eth0 -w capture.pcap
```

### NetworkMiner
Passive network forensics tool that reconstructs files, credentials, and sessions from a pcap automatically, with a friendlier GUI than Wireshark for artifact-hunting.

### Zeek (formerly Bro)
Generates structured logs (connections, DNS, HTTP, files) from a pcap or live traffic — better suited to bulk triage than manual packet inspection.

---

## 11. Steganography & Hidden Data

```bash
strings -n 8 file.bin | less     # readable text strings
zsteg image.png                  # LSB steganography in PNG/BMP
steghide info image.jpg          # check for a steghide payload
steghide extract -sf image.jpg   # extract, prompts for passphrase
stegsolve.jar                    # GUI: view bit planes, color channels
```
**Aperi'Solve** (web-based) runs multiple stego checks (zsteg, steghide, ELA, binwalk) on one upload — a fast first pass for CTF-style challenges.

---

## 12. Image/Video Manipulation Detection

### FotoForensics / Forensically (both web-based)
Error Level Analysis (ELA), clone/copy-move detection, noise analysis, metadata display — run directly in browser, good for a first pass on a suspect image.

### Ghiro
Self-hosted, automated image forensics platform: runs ELA, metadata extraction, and GPS mapping in bulk across many images.

---

## 13. Hashing & Known-File Filtering

```bash
sha256sum file        # cryptographic hash for integrity verification
md5sum file
ssdeep file            # fuzzy hashing — finds similar-but-not-identical files
```

### NSRL (National Software Reference Library) hash sets
A database of known-good file hashes (standard OS/application files). Loaded into Autopsy or used with `hfind` (TSK) to filter out irrelevant files and focus on what's unique to the case.
```bash
hfind -f nsrl_hashset.txt suspect_hashes.txt
```

---

## 14. Mobile Forensics

### ALEEAPP / iLEAPP
Free, script-based parsers for Android and iOS filesystem extractions — turn raw extracted data into readable reports (chats, call logs, locations, app data).
```bash
ileapp.py -t fs -i extraction_folder/ -o report/
```

### Cellebrite UFED / Magnet AXIOM
Commercial industry-standard suites for mobile acquisition and parsing, used in law enforcement and corporate investigations. Not free, but the de facto tools in professional settings.

### `abootimg` / `mkbootimg` unpackers
Unpack Android boot/recovery images to inspect the kernel and ramdisk.

---

## 15. Malware & Binary Analysis

### Ghidra
Free, NSA-developed disassembler/decompiler — the standard free tool for reverse engineering binaries found on disk or extracted from firmware.

### radare2 / Cutter
Command-line (`r2`) and GUI (`Cutter`) reverse engineering framework, lighter-weight alternative to Ghidra for quick binary inspection.
```bash
r2 -A suspicious_binary
```

### `strings`, `objdump`, `readelf`, `checksec`
Quick static triage before deeper reversing.
```bash
strings -n 8 binary | less
objdump -d binary | less        # disassembly
readelf -h binary               # ELF header info
checksec --file=binary          # security mitigations (NX, ASLR, canaries)
```

### VirusTotal / `hybrid-analysis`
Upload hashes or files for multi-engine detection and, for hybrid-analysis, automated sandbox behavior reports. Never upload sensitive/confidential evidence to public sandboxes.

---

## 16. All-in-One Suites & Distros

| Tool | Role |
|---|---|
| **Autopsy** | Free GUI suite built on The Sleuth Kit; disk analysis, keyword search, artifact modules |
| **SIFT Workstation** | Free Linux distro from SANS, pre-loaded with most tools in this guide |
| **CAINE** | Similar Linux forensics distro, Italian in origin, widely used in training |
| **Kali Linux** | General security distro; includes many carving, stego, and network tools |
| **EnCase / FTK (commercial)** | Industry-standard commercial suites for full-scope investigations and court-ready reporting |
| **Magnet AXIOM (commercial)** | Combines disk, mobile, and cloud artifact parsing in one platform |

---

## 17. OSINT & Provenance

- **Reverse image search**: Google Lens, TinEye, Yandex Images, Bing Visual Search
- **Content Credentials / C2PA**: contentcredentials.org/verify — checks cryptographically signed provenance data
- **SunCalc**: estimates time/date from shadow angles in a photo (chronolocation)
- **Bellingcat's Online Investigation Toolkit**: curated list of free OSINT tools, updated regularly

---

## Choosing where to start

- **"I have a disk image"** → `mmls` → `fsstat` → `fls`/`icat` (TSK) or just load it into **Autopsy**
- **"I have a RAM dump"** → **Volatility 3**
- **"I have a pcap"** → **Wireshark**/`tshark`, or **Zeek** for bulk triage
- **"I have firmware/a flash dump"** → `binwalk`/`unblob` first, then the matching filesystem extractor
- **"I have one suspicious file"** → `file` → `exiftool` → `binwalk`/`strings` → then case-specific tools (ELA for images, Ghidra for binaries)
- **"I need a timeline across everything"** → **Plaso**

## A note on legality and ethics

Only analyze data you own or have explicit authorization to examine. Many of these tools (packet capture, binary disassembly, memory acquisition) are also usable offensively — using them against systems or data you don't have permission to access is illegal in most jurisdictions regardless of intent.
