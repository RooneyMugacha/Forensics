# CTF Writeup: Partition Recovery (Forensics)

**Event:** MetaCTF  
**Category:** Digital Forensics / Data Recovery  
**Points:** 100  
**Files provided:** `usb.img`

---

## Challenge Description

> I was messing with trying to dual boot, and while trying to fix partitions, I accidentally deleted the one on my wedding flash drive I carelessly had plugged in! Please help me recover it.

---

## TL;DR

We created a safe working copy of the disk image, used **TestDisk** to locate and analyze the lost FAT32 partition, browsed the filesystem directly through the tool, and navigated to the `.Meta` directory to retrieve the flag.

---

## Step 1 - Initial Triage & Safeguarding the Evidence

Before performing any data recovery operations, it is a best practice in digital forensics to create a duplicate of the original evidence file. This ensures the original disk image remains pristine and unmodified.

```bash
$ cp original_usb.img usb.img
```

---

## Step 2 - Analyzing Partitions with TestDisk

With our disk image ready, we launched **TestDisk** to scan for lost, damaged, or deleted partition structures:

```bash
$ testdisk usb.img
```

After navigating through TestDisk's analysis options, the utility successfully detected the missing partition structure, identifying it as a **FAT32** filesystem (`522240` sectors).

---

## Step 3 - Browsing and Recovering from the Partition

Rather than immediately writing the partition table back to the raw image, we used TestDisk's interactive file browser to inspect the contents of the recovered partition. 

Navigating into the root directory, we located a hidden directory named `.Meta`:

```text
Directory / .Meta
```

Inside the `.Meta` folder, we accessed the `CTF` directory to retrieve the final objective.

---

## Flag

```
MetaCTF{n0t_ev3n_d3l3t10n_c4n_s3p4r4t3_u5}
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| **TestDisk** | Partition table analysis, scanning, and filesystem file browsing |
| **Linux Shell** | Safe image duplication and execution |

---

## Lessons / Notes for Next Time

- **Always isolate external storage devices** before modifying bootloaders, partition tables, or configuring dual-boot environments.
- **TestDisk** is exceptionally efficient for recovering deleted partitions without needing complex file-carving tools.