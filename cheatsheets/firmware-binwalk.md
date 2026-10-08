# Firmware / Unknown Blob Cheatsheet

```bash
file blob.bin
xxd blob.bin | head
binwalk blob.bin           # find embedded files
binwalk -e blob.bin        # extract
binwalk -Me blob.bin       # recursive extract
binwalk -E blob.bin        # entropy (compressed/encrypted regions)
unblob blob.bin            # robust alternative
```

## Filesystems
```bash
unsquashfs -d out/ root.squashfs
jefferson fw.jffs2 -d out/
ubireader_extract_files fw.ubi
simg2img sparse.img raw.img      # Android sparse images
```

## Hunt in extracted files
```bash
grep -rniE "password|passwd|secret|api[_-]?key|token" extracted/
find extracted/ -name "*.pem" -o -name "id_rsa*" -o -name "*.key"
strings -n 8 extracted/usr/bin/* | less
```

## Common problems
- Raw NAND with OOB/ECC bytes: page and spare sizes needed before stripping
- Byte-swapped dumps: try `dd conv=swab`
- High-entropy everywhere: likely encrypted
