# Images and Stego Cheatsheet

```bash
exiftool image.jpg
binwalk -e image.jpg
strings -n 8 image.jpg | less
zsteg -a image.png                  # LSB checks on PNG/BMP
steghide info image.jpg
steghide extract -sf image.jpg
```

Also try: StegSolve (bit planes, channels), Aperi'Solve (many checks at once), checking for data after the JPEG end marker `FF D9`.

## Manipulation checks
Error Level Analysis (FotoForensics, Forensically), clone detection, noise analysis, reverse image search (TinEye, Google Lens, Yandex).
