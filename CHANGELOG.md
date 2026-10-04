# Changelog

## 1.3.9

Quality/stability patch for cross-machine deployment.

- VirusTotal `last_analysis_stats` is normalized and stores `virustotal_engine_total = sum(category counts)` in case metrics.
- `undetected` is explicitly not interpreted as benign/harmless or false-positive evidence.
- VT engines remain one aggregated vendor-context source, not independent corroboration.
- Reporting rules separate registry lookup source, registrar, registrant/holder, and DNS/nameserver provider.
- CT wording is historical by default; recent issuance is not current operation without live-state corroboration.
- Suggestive historical urlscan/archive paths remain literal observations unless independently corroborated.
- Historical IP/ASN diversity cannot be summarized as migration without timeline corroboration.
- Installer preserves existing `cases/` on upgrade.
- Added `MIGRATION.md` for clean transfer to another machine.
- Added `bin/preflight.py` for safe dependency/credential checks without exposing secret values.

## 1.3.8

- Canonical runner enforcement and provenance.
- Runtime fault isolation and partial-case persistence.
- Interpretation hardening for registrar/DNS provider, CT/live TLS, VT context, and urlscan diversity.
