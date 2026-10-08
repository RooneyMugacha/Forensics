# Memory Forensics (Volatility 3) Cheatsheet

```bash
vol -f mem.dmp windows.info
vol -f mem.dmp windows.pslist
vol -f mem.dmp windows.pstree
vol -f mem.dmp windows.cmdline
vol -f mem.dmp windows.netscan
vol -f mem.dmp windows.malfind            # injected / suspicious memory regions
vol -f mem.dmp windows.dlllist --pid 1234
vol -f mem.dmp windows.filescan
vol -f mem.dmp windows.dumpfiles --pid 1234
vol -f mem.dmp windows.hashdump
vol -f mem.dmp windows.registry.hivelist
```

Linux: `linux.pslist`, `linux.bash`, `linux.lsof` (needs a matching symbol table).

## Workflow
1. `windows.info` to confirm the profile/OS build
2. `pslist` / `pstree` for odd parent-child relationships
3. `cmdline` and `netscan` on suspicious PIDs
4. `malfind` for injection
5. Dump files or memory of interest and analyze separately
