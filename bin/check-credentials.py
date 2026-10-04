#!/usr/bin/env python3
"""Safely report configured OSINT credential names without printing values."""
from pathlib import Path
import os, re, shlex, stat
KEYS = ["NETLAS_API_KEY","CENSYS_PAT","URLSCAN_API_KEY","VT_API_KEY","SHODAN_API_KEY","HUNT_API_KEY","HUNT_IO_TOKEN","GREYNOISE_API_KEY"]
path = Path.home()/'.osint_keys'
found = {k: ('environment' if os.environ.get(k) else None) for k in KEYS}
if path.exists():
    mode = path.stat().st_mode & 0o777
    print(f"credential_file: {path}")
    print(f"permissions: {oct(mode)} {'OK' if not (mode & 0o077) else 'TOO_BROAD (use chmod 600)'}")
    if not (mode & 0o077):
        pat = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
        for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
            m=pat.match(line)
            if m and m.group(1) in KEYS and m.group(2).strip() and not found[m.group(1)]:
                found[m.group(1)]='credentials_file'
else:
    print(f"credential_file: {path} (missing)")
for k in KEYS:
    print(f"{k}: {'OK ('+found[k]+')' if found[k] else 'MISSING'}")
