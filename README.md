# Hermes OSINT Hybrid Framework v1.3.9

A modular OSINT framework for Hermes Agent that keeps **evidence collection and provenance** at the center while adding controlled fuzzy search, company/public-identity/vendor workflows, and cross-module handoffs.

## Why modular

Do not load one huge OSINT prompt for every case. The master `SKILL.md` routes to the smallest relevant module:

```text
osint-hybrid
├── domain       # infrastructure, DNS, CT, archives, passive pivots
├── company      # legal entity / filings / ownership signals
├── person       # public professional identity verification
├── username     # public handle discovery + corroboration
└── vendor       # third-party cyber/privacy due diligence
```

This is especially useful with local models where context budget matters.

## Domain runner

```bash
python3 bin/domain_osint.py example.com
```

Outputs a case folder with normalized evidence, raw source captures, findings, and report.

## Methodology

The framework uses ideas from Berkeley Protocol, Bellingcat-style verification, public FBI/DOJ infrastructure-correlation patterns, practical OSINT pivoting, and design ideas from the MIT-licensed `mtjikuzu/hermes-osint-skill`.

See `ATTRIBUTION.md` and `docs/Hermes_OSINT_Hybrid_Framework_v1_3.pdf`.

## v1.3.3 — resilient Certificate Transparency collection

The `crt.sh` adapter now distinguishes service failure from a genuine empty result.
It retries temporary HTTP/network failures with bounded backoff, rejects HTML error
pages returned as HTTP 200, and optionally falls back to crt.sh's public PostgreSQL
interface when the local `psql` client is available.

Status semantics:
- `OK` — primary HTTP endpoint returned valid CT data.
- `PARTIAL` — primary endpoint failed, but fallback produced usable CT evidence.
- `NO_RESULT` — a CT source responded successfully and returned no observations.
- `RATE_LIMITED` — primary endpoint returned HTTP 429.
- `UNAVAILABLE` — no trustworthy CT result could be obtained.

A temporary crt.sh outage must never be interpreted as evidence that a domain has no
certificate history.


### v1.3.3 current-state validation
The runner now validates a bounded set of CT-derived hostnames with a normal TLS client handshake. CT remains historical evidence; only the live-tls adapter may label a hostname as currently serving TLS. urlscan can operate in public mode without a key; Hunt.io requires HUNT_API_KEY/HUNT_IO_TOKEN; Shodan requires a configured local CLI/API account.


## v1.3.4 — source capability and methodology coverage

Each run now records a **Source Capability Matrix** in both `case.yaml` and `report.md`.
For every source it records access mode, whether a credential is present, whether the source
actually ran, runtime status (`OK`, `LIMITED`, `RATE_LIMITED`, `UNAVAILABLE`, `SKIPPED`, etc.),
and the known limitation that affects methodology coverage.

New enrichment adapters:
- Netlas (`NETLAS_API_KEY`)
- VirusTotal (`VT_API_KEY`)
- Censys (`CENSYS_PAT`)
- Robtex Free Passive DNS (no key; strict public rate limit)

The report separately labels **Core methodology coverage** and **Optional enrichment coverage**.
A present API key is never treated as proof that the source was successfully usable.


## v1.3.5 — secure local credential loading

The runner can now read API credentials directly from `~/.osint_keys` **without sourcing that file into the Hermes shell environment**. This prevents Hermes terminal snapshots/cache from inheriting API secrets.

Recommended file:

```bash
chmod 600 ~/.osint_keys
```

Example contents:

```bash
export NETLAS_API_KEY='...'
export CENSYS_PAT='...'
export URLSCAN_API_KEY='...'
export VT_API_KEY='...'
export SHODAN_API_KEY='...'
```

Then start Hermes normally — do **not** run `source ~/.osint_keys` first. The `domain_osint.py` child process reads the file itself, whitelists known credential names, never executes the file, and never prints secret values. Existing environment variables still take precedence.

The Source Capability Matrix now reports `Credential source` as `credentials_file`, `environment`, `absent`, or `n/a`. Use `--no-credentials-file` for an environment-only run or `--credentials-file PATH` to choose another local file.

Safe credential check (values are never printed):

```bash
python3 bin/check-credentials.py
```

For Shodan, the matrix may show the key as present while runtime is still `UNAVAILABLE` if the local Shodan CLI itself has not been initialized. That distinction is intentional.


## v1.3.8 — canonical runner provenance

Domain investigations must use the bundled `bin/domain_osint.py`; Hermes should not create or patch ad-hoc replacement collectors during a normal investigation. The case now records the resolved runner path, SHA-256, execution mode (`canonical_runner` or `noncanonical_copy`), and canonical-layout flag.

Verify the installed engine without exposing credentials:

```bash
python3 bin/domain_osint.py --self-check
```

If the runner fails during an investigation, preserve the failure instead of silently substituting a new script. Code changes are appropriate only when the operator explicitly requests a skill update/debugging session.

## Runtime fault isolation (v1.3.8)

- Treat `bin/domain_osint.py` as the canonical execution engine.
- Never patch, rewrite, substitute, or generate a replacement investigation script during a normal case run.
- Never delete `cases/`, prior case directories, raw artifacts, or reports as a recovery step.
- A failure in one source (for example urlscan, Netlas, Censys, VirusTotal, or Shodan) is recorded as that adapter's `ERROR`, while remaining adapters continue.
- The runner persists partial case artifacts even after an isolated adapter failure or user interruption.
- Debugging or modifying the runner is a separate development task and requires an explicit user request; do not mix code repair with evidence collection.


### v1.3.8 interpretation hardening

This release adds report/model guardrails for registrar-vs-DNS-provider separation, CT-vs-live-TLS separation, conservative recent-certificate wording, VirusTotal vendor-count handling, and urlscan IP-diversity ambiguity.

## v1.3.9 — interpretation/schema stabilization

This release tightens the boundary between collection and analyst interpretation:

- separates registry lookup source, registrar, registrant/holder, and DNS provider semantics;
- treats CT as historical issuance and requires live-state corroboration before using activity language;
- normalizes VirusTotal `last_analysis_stats` with an explicit `engine_total` denominator;
- forbids treating `undetected` as benign/harmless or as evidence of false positives;
- keeps suggestive historical URL/path names as literal observations unless independently corroborated;
- keeps historical IP/ASN diversity ambiguous unless a migration inference is supported by timeline evidence;
- installer preserves existing `cases/` when upgrading an installed skill.

For transfer to another machine, read `MIGRATION.md` before installing. API credentials are intentionally not included in the ZIP.

## Portfolio & Professional Services

Explore my Linux infrastructure, cybersecurity, and AI automation work: [ta551.info](https://ta551.info/).
