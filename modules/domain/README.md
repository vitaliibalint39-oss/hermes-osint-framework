# Domain OSINT Investigation Skill v1.3.9

A passive/public-source domain investigation skill plus a dependency-light Python runner.

## Quick start

```bash
cd domain_osint_skill_v1_2
python3 bin/domain_osint.py example.com
```

Install the convenience command:

```bash
./bin/install.sh
# Then, if ~/.local/bin is in PATH:
domain-osint example.com
```

The runner creates:

```text
cases/CASE-YYYY-MM-DD-XXXXXX/
  case.yaml
  evidence.jsonl
  findings.yaml
  raw/
  screenshots/
  report.md
```

## Optional integrations and credentials

The recommended setup is a private local file at `~/.osint_keys`. **Do not source it before starting Hermes.** The runner reads it directly inside its own child process.

```bash
chmod 600 ~/.osint_keys
```

Supported credential names include `NETLAS_API_KEY`, `CENSYS_PAT`, `URLSCAN_API_KEY`, `VT_API_KEY`, `SHODAN_API_KEY`, `HUNT_API_KEY` / `HUNT_IO_TOKEN`, and optional `GREYNOISE_API_KEY`.

Example:

```bash
domain-osint example.com --username known_public_handle
```

Use `--credentials-file PATH` for another file or `--no-credentials-file` to use environment variables only. Existing environment variables override file values. Shodan still requires its local CLI where that adapter uses the CLI; Sherlock uses the local `sherlock` command.

For a strict public-source pass without commercial third-party intelligence:

```bash
domain-osint example.com --no-third-party-intel
```

## Scope

The runner does not perform exploitation, authentication attempts, credential testing, bypasses, active vulnerability scanning, or automatic identity attribution. It collects passive observations and preserves provenance for analyst review.

### Certificate Transparency resilience (v1.3.1)
`crt.sh` collection uses up to four bounded attempts with backoff. Temporary 429/500/502/503/504 responses, network failures, or HTML error bodies are not treated as `NO_RESULT`. If the HTTP JSON endpoint remains unavailable and `psql` is installed, the runner attempts the public crt.sh PostgreSQL service. Successful fallback collection is marked `PARTIAL` so provenance remains explicit.


## v1.3.2 safeguards

- Fall back to registry WHOIS when authoritative RDAP is unavailable for a ccTLD.
- Treat Wayback HTTP 400 as a request error, not as absence of archives.
- Deduplicate CT results before analyst review.
- Suppress reverse-IP ownership pivots when Cloudflare edge infrastructure is detected.
