#!/usr/bin/env python3
"""Safe local preflight for Hermes OSINT Hybrid. Does not print secret values."""
from pathlib import Path
import os, shutil, stat, re

TOOLS = ["python3", "dig", "whois", "openssl", "psql", "shodan", "sherlock"]
KEYS = ["NETLAS_API_KEY","CENSYS_PAT","URLSCAN_API_KEY","VT_API_KEY","SHODAN_API_KEY","HUNT_API_KEY","HUNT_IO_TOKEN","GREYNOISE_API_KEY"]

print("Hermes OSINT Hybrid preflight")
print("\nLocal tools:")
for t in TOOLS:
    p = shutil.which(t)
    print(f"  {t}: {'OK '+p if p else 'MISSING/OPTIONAL'}")

path = Path.home()/'.osint_keys'
print("\nCredential file:")
print(f"  path: {path}")
found = {k: ('environment' if os.environ.get(k) else None) for k in KEYS}
if path.exists():
    mode = path.stat().st_mode & 0o777
    safe = not (mode & 0o077)
    print(f"  permissions: {oct(mode)} {'OK' if safe else 'TOO_BROAD (use chmod 600)'}")
    if safe:
        pat = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
        for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
            m=pat.match(line)
            if m and m.group(1) in KEYS and m.group(2).strip() and not found[m.group(1)]:
                found[m.group(1)]='credentials_file'
else:
    print("  status: missing (public-only collection still works)")

print("\nCredential presence (values hidden):")
for k in KEYS:
    print(f"  {k}: {'OK ('+found[k]+')' if found[k] else 'MISSING'}")
