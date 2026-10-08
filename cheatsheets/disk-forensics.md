# Disk Forensics Cheatsheet

## Preserve
```bash
sha256sum disk.dd
dc3dd if=/dev/sdX of=evidence.dd hash=sha256 log=acquire.log   # use a write blocker on real evidence
```

## Identify
```bash
file disk.dd
mmls disk.dd                    # partitions + start sectors
fsstat -o <offset> disk.dd      # filesystem details
```

## Browse and extract (Sleuth Kit)
```bash
fls -r -o <offset> disk.dd                       # files, deleted marked with *
fls -r -m / -o <offset> disk.dd > bodyfile.txt   # for timelines
icat -o <offset> disk.dd <inode> > out.file
istat -o <offset> disk.dd <inode>                # timestamps
```

## Mount read-only
```bash
sudo mount -o ro,loop,noexec,offset=$((512*2048)) disk.dd /mnt/evidence
```

## Timeline
```bash
mactime -b bodyfile.txt -d > timeline.csv
log2timeline.py plaso.dump disk.dd
psort.py -o dynamic plaso.dump -w super_timeline.csv
```

## Carving
```bash
photorec disk.dd
foremost -i disk.dd -o carved/
bulk_extractor -o be_out disk.dd
```

## Keyword search
```bash
strings -a -t d disk.dd | grep -i "keyword"
```
