---
name: domain-osint-investigation
description: Structured, evidence-focused OSINT workflow for investigating a domain, its public infrastructure, historical footprint, related identifiers, and possible relationships. Designed for passive/public-source research and authorized assessments. Separates observations from inference, requires corroboration, records provenance, and produces confidence-scored findings.
version: 1.3.9
---

# Domain OSINT Investigation Skill

## Purpose

Use this skill to investigate a domain using public/open sources and, where appropriate, non-intrusive checks against systems the analyst is authorized to assess.

The workflow is inspired by:
- Berkeley Protocol principles for lawful, ethical, reproducible digital open-source investigation.
- Bellingcat-style verification and transparent sourcing.
- Public FBI/DOJ cyber-investigation materials showing correlation across domains, infrastructure, identifiers, timelines, and corroborating evidence.
- Practical OSINT pivoting patterns used in professional domain research.

**Important:** This is not an official FBI methodology or internal FBI manual. "FBI-style" in this skill means evidence correlation patterns observable in public FBI/DOJ materials.

## Safety and Scope Rules

Before starting, define scope.

Allowed by default:
- Public DNS and RDAP/WHOIS information.
- Certificate Transparency data.
- Search engines and public web pages.
- Web archives.
- Public corporate records and public code repositories.
- Publicly accessible passive-infrastructure databases.
- Non-invasive retrieval of the target's public web content.

Do not perform unless explicitly authorized and necessary:
- Authentication attempts or credential testing.
- Exploitation or vulnerability validation.
- Bypassing access controls.
- Accessing private, leaked, stolen, or unlawfully obtained data.
- Destructive actions or service disruption.
- High-volume or evasive scanning.

If authorization is ambiguous, remain passive.

## Core Analytical Rules

1. Collect before concluding.
2. One indicator is not attribution.
3. Shared infrastructure does not imply shared ownership.
4. Prefer two or more independent sources for material findings.
5. Preserve timestamps, source URLs, queries, and raw observations.
6. Separate OBSERVATION, INFERENCE, and UNKNOWN.
7. Record plausible alternative explanations.
8. Treat historical context as first-class evidence.
9. Never inflate confidence to fill missing evidence.
10. Make findings reproducible by another analyst.


## Mandatory Execution Rule (v1.3.7)

For normal domain investigations, **always use the bundled canonical runner**:

```bash
python3 bin/domain_osint.py example.com
```

Do not generate, patch, or substitute an ad-hoc investigation script. Do not create `investigate_<domain>.py` or similar temporary collectors. If the canonical runner fails, preserve the error and ask for/perform an explicit code fix only when the user requests debugging or an update. The investigation result must come from the bundled runner so provenance, capability status, credential isolation, and evidence normalization remain comparable across cases.

## Required Inputs

At minimum:

```yaml
target_domain: example.com
objective: "Identify public infrastructure and potentially related domains."
scope: passive-public
case_id: CASE-YYYY-MM-DD-001
```

Optional:

```yaml
known_artifacts:
  - email@example.com
  - 192.0.2.10
  - organization name
constraints:
  - no active scanning
  - public sources only
```

## Workflow

### Phase 1 - Case Setup

Create a case record:

```text
Case ID:
Target:
Objective:
Scope:
Analyst:
Start time UTC:
Known artifacts:
Explicit exclusions:
```

State the investigative question before collecting data.

### Phase 2 - Baseline Registration Profile

Collect:
- Domain and TLD.
- Registrar.
- Creation, update, and expiration dates when public.
- Domain status.
- DNSSEC status.
- Public registrant organization/country when legally available.

Preferred sources:
- ICANN RDAP.
- Registrar RDAP.
- Lawfully available historical registration sources.

For every observation record:

```text
Source:
Retrieved UTC:
Query:
Observation:
Raw/reference artifact:
```

### Phase 3 - DNS Profile

Collect the public records that exist:
- A / AAAA
- NS
- MX
- TXT
- CNAME
- SOA
- CAA

Useful local commands for ordinary public DNS resolution:

```bash
dig example.com A +short
dig example.com AAAA +short
dig example.com NS +short
dig example.com MX +short
dig example.com TXT +short
dig example.com CNAME +short
dig example.com SOA +short
dig example.com CAA +short
```

Do not infer ownership solely from DNS co-location.

### Phase 4 - Infrastructure Mapping

For each observed IP, map publicly available attributes:
- IP address.
- ASN.
- Network prefix.
- Provider / organization.
- Country/region at infrastructure level.
- Hosting/CDN indicators.

Graph the relationship:

```text
DOMAIN
  -> IP
      -> ASN
          -> Provider
  -> NS
  -> MX
```

Classify infrastructure:
- Shared hosting.
- CDN/reverse proxy.
- Dedicated/likely dedicated.
- Cloud platform.
- Unknown.

**Analytical caution:** a shared IP is normally weak evidence of common control.

### Phase 5 - TLS / Certificate Transparency

Use public Certificate Transparency sources to collect:
- Certificate subject.
- Subject Alternative Names (SANs).
- Issuer.
- Validity period.
- Publicly visible fingerprints or certificate identifiers.

Look for:
- Subdomains.
- Historical hostnames.
- Additional domains appearing in the same relevant certificate context.

Label certificate-derived relationships as technical relationships until independently corroborated.

### Phase 6 - Historical Infrastructure

Search public historical sources for changes in:
- A / AAAA records.
- Nameservers.
- MX records.
- Certificates.
- Registration data where legally available.

Build a timeline:

```text
DATE/TIME | ARTIFACT | OLD VALUE | NEW VALUE | SOURCE | CONFIDENCE
```

Historical continuity can be more informative than a current snapshot.

### Phase 7 - Pivoting

Pivot from validated artifacts.

#### IP pivot

```text
Domain -> IP -> other publicly observed domains
```

Default interpretation: **infrastructure association**, not common ownership.

#### Nameserver pivot

```text
Domain -> NS -> other domains
```

Custom/uncommon nameservers generally carry more analytical weight than large shared DNS providers.

#### MX pivot

```text
Domain -> mail infrastructure -> related domains
```

Custom mail infrastructure can be more distinctive than a mass email provider.

#### Certificate pivot

```text
Domain -> certificate/SAN history -> hostnames/domains
```

#### Registration-artifact pivot

When lawfully public:
- Organization.
- Email.
- Phone.
- Address.
- Registrar patterns.
- Creation-date clusters.

Never attribute ownership from one registration field alone.

### Phase 8 - Current Web Content

Record publicly visible:
- Site title.
- Claimed organization.
- Contact emails.
- Public phone numbers.
- Business addresses.
- Social links.
- Copyright notices.
- Privacy/terms pages.
- Company registration references.
- Distinctive phrases and branding.
- Public analytics/tracking identifiers when visible in page source.
- Favicons and embedded third-party services.

Preserve URLs and collection timestamps.

### Phase 9 - Historical Web Content

Use public archives to identify:
- Previous organization names.
- Old contact details.
- Historical email addresses.
- Previous logos/branding.
- Changes in business claims.
- Previous social links.
- Historical products/services.

Add relevant observations to the master timeline.

### Phase 10 - Search-Engine Correlation

Useful query patterns:

```text
"example.com"
"@example.com"
"example.com" company
"example.com" username
"example.com" email
"example.com" filetype:pdf
```

Look for public:
- Documents.
- Job postings.
- Social profiles.
- Corporate listings.
- GitHub/code references.
- Technical documentation.
- News or research reports.

Do not collect unrelated sensitive personal information merely because it is searchable.

### Phase 11 - Identifier Correlation

Convert validated identifiers into a relationship graph:

```text
DOMAIN
  |-- EMAIL
  |     `-- public references/accounts
  |-- USERNAME
  |     `-- public profiles
  |-- COMPANY
  |     |-- public corporate records
  |     `-- public organizational references
  `-- INFRASTRUCTURE
        |-- IP
        |-- NS
        |-- MX
        `-- certificates
```

Every edge must contain:
- Source.
- Timestamp.
- Relationship type.
- Confidence.
- Alternative explanation if applicable.

### Phase 12 - Corroboration

A material relationship should preferably be supported by at least two independent evidence classes.

Example:

```text
Domain A
  |-- same uncommon custom NS ---------+
  |                                     |
Domain B                                +-- possible relationship
  |                                     |
  |-- same public contact email --------+
  `-- same historical company name ----+
```

Independence matters. Three databases that copy the same source are not three independent sources.

### Phase 13 - Confidence Model

Use three levels.

#### LOW

One weak or ambiguous indicator.

Example:
- Same shared IP.

Wording:
> Possible technical association. Insufficient evidence for attribution.

#### MEDIUM

Multiple mutually consistent indicators, but identity/control is not independently proven.

Example:
- Same custom nameserver.
- Similar creation window.
- Highly similar site structure.

Wording:
> Multiple indicators support a possible relationship. Common ownership or control is not independently confirmed.

#### HIGH

Multiple independent, specific, mutually reinforcing sources.

Example:
- Same unique public contact identity.
- Historical infrastructure continuity.
- Public corporate record linking the entity.

Wording:
> Multiple independent sources strongly support the assessed relationship.

HIGH is not absolute certainty. State residual uncertainty.

### Phase 14 - Evidence Preservation

For material evidence, create an evidence record:

```yaml
evidence_id: CASE-001-E014
collected_utc: 2026-09-24T04:15:00Z
source: "Public CT database"
url: "https://..."
query: "example.com"
observation: "Certificate record contains example.com and api.example.com"
relationship: "technical hostname association"
confidence: high
notes: "No ownership conclusion from certificate alone"
```

Where useful preserve:
- Screenshot.
- Raw response.
- Exported result.
- Cryptographic hash of a saved artifact.

Do not claim chain-of-custody properties that were not actually maintained.

### Phase 15 - Analytical Separation

Every important finding should be expressible in three buckets.

**OBSERVATION**
> On the observed date, the domain resolved to 192.0.2.10.

**INFERENCE**
> Two domains may share infrastructure.

**UNKNOWN**
> Available open-source evidence does not establish common ownership.

### Phase 16 - Final Report

Produce the report in this order:

1. Executive Summary
2. Scope and Limitations
3. Collection Method
4. Domain Profile
5. DNS and Infrastructure
6. TLS/Certificate Findings
7. Historical Timeline
8. Related Artifacts and Pivots
9. Corroborated Relationships
10. Alternative Explanations
11. Confidence Assessment
12. Unknowns / Intelligence Gaps
13. Evidence Register
14. Sources

Use the template in `templates/report-template.md`.


## Automated Collection Adapters

Use adapters to automate passive collection while preserving provenance. An adapter is a collector, not an attribution engine. Each adapter must return observations in the unified evidence schema below.

### Adapter Safety Defaults

- Passive/public-source mode by default.
- No credential testing, exploitation, bypass, or evasive scanning.
- Respect provider terms, API quotas, and rate limits.
- Prefer exact-target queries over broad harvesting.
- Save the original query and collection time.
- Treat third-party results as leads until corroborated.
- If an API key is unavailable, mark the adapter `UNAVAILABLE` and continue with other sources.

### Unified Evidence Schema

Every adapter should normalize its result to records shaped like:

```yaml
evidence_id: CASE-001-E001
case_id: CASE-001
source_adapter: rdap|dig|crtsh|wayback|shodan|huntio|urlscan|sherlock
source_name: "ICANN RDAP"
source_url: "https://..."
query: "example.com"
collected_utc: "2026-09-24T04:15:00Z"
artifact_type: domain|ip|asn|dns|certificate|url|username|archive
artifact: "example.com"
relationship: "resolves_to|registered_by|certificate_san|archived_url|observed_on|username_match"
observation: "Public observation stated without interpretation."
raw_ref: "path/to/raw-result.json"
confidence: low|medium|high
notes: "Limitations or alternative explanation."
```

The `observation` field must remain factual. Put interpretation in `notes` or the later analytical phase.

### Adapter 1 - `dig` / DNS

Purpose: collect current public DNS records.

Recommended commands:

```bash
dig example.com A +noall +answer
dig example.com AAAA +noall +answer
dig example.com NS +noall +answer
dig example.com MX +noall +answer
dig example.com TXT +noall +answer
dig example.com CNAME +noall +answer
dig example.com SOA +noall +answer
dig example.com CAA +noall +answer
```

Normalize each returned record as a separate evidence item. Save TTL where available. Do not interpret shared DNS providers as evidence of common ownership.

### Adapter 2 - RDAP

Purpose: registration baseline from standards-based public registration data.

Preferred sequence:
1. Query the authoritative RDAP bootstrap/registry endpoint.
2. Record registrar, public status codes, events, nameservers, and public entity data.
3. Preserve the raw JSON response.

Example with a registry endpoint discovered for the TLD:

```bash
curl -sS 'https://<rdap-endpoint>/domain/example.com' -o raw/rdap-example.com.json
```

Do not hard-code one RDAP provider for all TLDs. If privacy/redaction is present, record it as a limitation rather than trying to bypass it.

### Adapter 3 - `crt.sh` / Certificate Transparency

Purpose: discover public certificate history and hostnames.

Example passive query:

```bash
curl -sS 'https://crt.sh/?q=%25.example.com&output=json' -o raw/crtsh-example.com.json
```

Normalize:
- observed certificate names;
- issuer;
- not-before / not-after;
- certificate/log identifier where available.

Deduplicate repeated CT entries before analysis. A SAN relationship is a technical observation, not proof of common ownership.

### Adapter 4 - Wayback / CDX

Purpose: identify historical URLs and archived snapshots.

Example query:

```bash
curl -sS 'https://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&filter=statuscode:200&filter=collapse:digest' \
  -o raw/wayback-example.com.json
```

Use snapshots to establish historical content, contacts, branding, redirects, or technology changes. Record snapshot timestamp separately from collection timestamp.

### Adapter 5 - Shodan

Purpose: passive enrichment of already-known public IPs/domains using a configured Shodan account.

Use the official CLI/API only when credentials are configured. Example host enrichment for an already observed IP:

```bash
shodan host 192.0.2.10
```

Record banners, ports, organization/ASN metadata, and observation timestamps supplied by Shodan. Do not treat stale Shodan observations as current state. Do not broaden into active scanning unless explicit authorization exists.

### Adapter 6 - Hunt.io

Purpose: passive infrastructure/context enrichment when a Hunt.io account is configured.

Implementation rule:
- use the currently documented Hunt.io CLI/API or web workflow;
- store exact query, result timestamp, and returned source metadata;
- do not invent endpoints or parameters if the local integration is not configured;
- normalize domain, IP, certificate, and infrastructure relationships into the same evidence schema.

If the integration is unavailable, emit:

```yaml
status: UNAVAILABLE
source_adapter: huntio
reason: "API/CLI integration not configured"
```

### Adapter 7 - urlscan.io

Purpose: obtain public historical scan observations for a domain/URL.

When using the public search/API, query the exact domain first and capture:
- scan time;
- submitted/final URL;
- resolved IPs;
- visible technologies/resources;
- linked domains where relevant.

Prefer existing public scans. Do not submit a fresh scan of a third-party target when doing so would exceed the declared passive-only scope.

### Adapter 8 - Sherlock

Purpose: verify whether a validated username appears on public sites. This adapter is only used after a username has been obtained from a relevant public artifact.

Example:

```bash
sherlock validated_username --print-found --csv
```

Rules:
- do not generate or brute-force username permutations;
- use only usernames relevant to the investigation;
- a username match alone does not establish that accounts belong to the same person;
- corroborate with public profile content or other independent identifiers.

### Adapter Orchestration Order

Default passive sequence:

```text
TARGET DOMAIN
   |
   +--> RDAP
   +--> DIG/DNS
   +--> CT/crt.sh
   +--> Wayback
   |
   +--> validated IPs ------> Shodan / Hunt.io
   |
   +--> public URLs --------> urlscan.io historical observations
   |
   `--> validated username -> Sherlock
                 |
                 v
        NORMALIZED EVIDENCE
                 |
                 v
       DEDUPLICATION + TIMELINE
                 |
                 v
          CORROBORATION
                 |
                 v
        CONFIDENCE ASSESSMENT
                 |
                 v
               REPORT
```

### Deduplication Rules

Before analysis:
- normalize domain names to lowercase/punycode as appropriate;
- normalize IP literals;
- remove exact duplicate DNS/CT/archive observations;
- preserve separate timestamps when the same artifact was observed at different times;
- do not merge records from separate sources merely because the displayed value matches.

### Adapter Failure Handling

An individual source failing must not abort the case. Record one of:

```text
OK           data collected
NO_RESULT    source queried successfully, nothing relevant returned
UNAVAILABLE  credentials/integration/provider unavailable
RATE_LIMITED provider quota/rate limit reached
ERROR        collection failed; preserve error context
OUT_OF_SCOPE requested step would exceed authorization/scope
```

Continue with independent adapters where possible.

### Automated Report Assembly

After collection, Hermes should:
1. Load normalized evidence records.
2. Group by domain, IP, DNS, certificate, URL, identifier, and time.
3. Build a chronological timeline.
4. Generate candidate relationships.
5. Require corroboration before promoting a candidate relationship to a finding.
6. Assign LOW/MEDIUM/HIGH confidence using the existing model.
7. Generate the final report using `templates/report-template.md`.
8. List adapter failures and intelligence gaps under limitations.

### Minimal Machine-Readable Case Layout

Recommended output structure:

```text
cases/CASE-YYYY-MM-DD-001/
  case.yaml
  evidence.jsonl
  findings.yaml
  raw/
    rdap-*.json
    dns-*.txt
    crtsh-*.json
    wayback-*.json
    shodan-*.json
    huntio-*.json
    urlscan-*.json
    sherlock-*.csv
  screenshots/
  report.md
```

This layout separates raw collection from normalized evidence and analytical findings.

## v1.2 Automated Runner

The package includes a dependency-light Python runner at `bin/domain_osint.py`. It implements the passive adapter orchestration described above and writes a reproducible case folder.

### Install the convenience command

```bash
cd domain_osint_skill_v1_2
./bin/install.sh
```

This installs a launcher at `~/.local/bin/domain-osint`. If that directory is not in `PATH`, call the Python script directly.

### Basic use

```bash
domain-osint example.com
```

Equivalent direct invocation:

```bash
python3 bin/domain_osint.py example.com
```

Strict public-source pass without Hunt.io or Shodan:

```bash
domain-osint example.com --no-third-party-intel
```

Use a validated public username for the optional Sherlock adapter:

```bash
domain-osint example.com --username known_public_handle
```

Credential handling (v1.3.5):

Prefer a private local `~/.osint_keys` file and let the runner read it directly. Do not require the user to `source` secrets into the parent Hermes shell. The credential file is parsed as data, never executed, and only whitelisted variable names are accepted. It should be mode `600`. Environment variables remain supported and take precedence.

Supported names include `NETLAS_API_KEY`, `CENSYS_PAT`, `URLSCAN_API_KEY`, `VT_API_KEY`, `SHODAN_API_KEY`, `HUNT_API_KEY` / `HUNT_IO_TOKEN`, and optional `GREYNOISE_API_KEY`.

Shodan uses the locally installed/configured official `shodan` CLI where applicable. Sherlock uses the locally installed `sherlock` command. Missing tools or credentials do not abort the case; the adapter is recorded as `UNAVAILABLE`, `LIMITED`, or `SKIPPED` as appropriate. Never print or persist secret values in reports, logs, snapshots, or evidence records.

### Runner outputs

```text
cases/CASE-YYYY-MM-DD-XXXXXX/
  case.yaml
  evidence.jsonl
  findings.yaml
  raw/
  screenshots/
  report.md
```

- `case.yaml` records target, objective, scope, timing, runner version, and adapter status.
- `evidence.jsonl` contains one normalized evidence record per line.
- `findings.yaml` contains only candidate technical relationships; it explicitly disables automated attribution.
- `raw/` preserves source JSON and CLI output.
- `report.md` is assembled automatically from the normalized evidence.

### Runner design rules

1. The runner is collection-first, not attribution-first.
2. It never converts a shared IP, certificate, username, or third-party intelligence hit directly into identity/ownership attribution.
3. It does not perform active vulnerability scanning.
4. It uses IANA RDAP service discovery rather than hard-coding one registry for all TLDs.
5. It caps high-volume normalized archive results while preserving the full raw response.
6. Each adapter failure is isolated so independent collection continues.
7. Candidate corroboration in `findings.yaml` means the same artifact appeared in multiple adapters; analyst review is still required.

### Useful CLI controls

```bash
# custom output root
domain-osint example.com --output-base ~/osint-cases

# custom case ID
domain-osint example.com --case-id CASE-2026-001

# skip one or more collectors
domain-osint example.com --skip wayback --skip urlscan

# validated username pivot
domain-osint example.com --username public_handle
```

### Operational note

The runner is intentionally dependency-light and relies on Python's standard library. `dig`, Shodan, and Sherlock are used only when present locally. Provider APIs remain subject to their current terms, authentication requirements, quotas, and schema changes.

## Source Quality Ranking

Prefer sources in this approximate order, while considering context:

1. First-party/authoritative public records.
2. Direct technical observations and standards-based registries.
3. Reputable archives and established technical intelligence sources.
4. Credible journalism/research with transparent sourcing.
5. Aggregators.
6. Unverified user-generated claims.

Do not turn this ranking into an automatic truth score. A lower-tier source can contain a correct lead that must be corroborated.

## Stop Conditions

Stop or narrow the investigation when:
- The objective is answered with sufficient evidence.
- Further collection would exceed scope.
- Additional pivots produce mostly unrelated personal data.
- A requested step requires unauthorized access or exploitation.
- A key conclusion cannot be corroborated; report the gap instead of forcing attribution.

## Output Quality Checklist

Before finalizing, verify:

- [ ] Scope is stated.
- [ ] Collection timestamps are recorded.
- [ ] Sources are linked or precisely identified.
- [ ] Observation and inference are separated.
- [ ] Shared hosting/CDN ambiguity is addressed.
- [ ] Historical evidence is included where relevant.
- [ ] Material findings have corroboration or an explicit caveat.
- [ ] Alternative explanations are documented.
- [ ] Confidence language matches evidence strength.
- [ ] Unknowns are explicitly listed.
- [ ] No unauthorized-access steps were used.
- [ ] Another analyst could reproduce the main findings.

## References

See `docs/references.md` for the methodological and public-source basis.


## v1.3.2 safeguards

- Fall back to registry WHOIS when authoritative RDAP is unavailable for a ccTLD.
- Treat Wayback HTTP 400 as a request error, not as absence of archives.
- Deduplicate CT results before analyst review.
- Suppress reverse-IP ownership pivots when Cloudflare edge infrastructure is detected.


## CANONICAL RUNNER / FAULT ISOLATION

For normal domain investigations, execute the installed `bin/domain_osint.py`. Do not create `investigate_*.py`, patch the installed runner, or delete prior case directories when one adapter fails. The runner isolates adapter failures and continues automatically. Read the resulting `report.md` and `case.yaml` after completion.


## v1.3.8 interpretation rules

1. DNS nameservers identify authoritative DNS/provider context, never the registrar by themselves.
2. Certificate Transparency is historical issuance evidence; current activity requires current DNS/TLS/HTTP validation.
3. VirusTotal engine totals are aggregated vendor reputation context and must not be treated as independent-source counts.
4. urlscan IP diversity is descriptive only unless timeline/corroboration supports a specific infrastructure-change inference.
5. Prefer conservative wording when current and historical sources disagree.

## v1.3.9 reporting guardrails

- Keep `Registry lookup source`, `Registrar`, `Registrant/Holder`, `DNS provider`, and `Nameserver provider` as separate fields.
- CT is historical issuance evidence. Use `recent certificate issuance activity observed`; do not call CT-only hostnames active.
- For VirusTotal `last_analysis_stats`, use the runner-provided `engine_total` as the only denominator. Never equate `undetected` with benign/harmless or false positive.
- Historical path names from urlscan/archives are observations, not intent. Terms such as `checker`, `bitcoin`, `admin`, or similar strings do not establish fraud, phishing, criminality, or ownership by themselves.
- Multiple historical IPs/ASNs are ambiguous and must not be summarized as a migration without timeline-based corroboration.
