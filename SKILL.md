---
name: osint-hybrid-investigation
version: 1.3.9
description: Modular OSINT investigation router for domain/infrastructure, company due diligence, individual verification, username pivots, and vendor cyber-risk assessment. Uses evidence-first collection, explicit provenance, fuzzy-search controls, relationship-confidence scoring, and report generation. Public-source/passive by default.
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [osint, investigation, due-diligence, domain, company, username, vendor-risk, evidence]
    category: research
---

# OSINT Hybrid Investigation

## Purpose

Use this as a **router**, not as one giant investigation prompt. Load only the module(s) needed for the current question. This keeps context use predictable and reduces false associations.

The framework combines:
- evidence handling and reproducibility principles inspired by the Berkeley Protocol;
- verification/transparency practices associated with Bellingcat-style investigations;
- public FBI/DOJ-style infrastructure correlation patterns (public materials only, not an internal FBI manual);
- practical pivot discipline from professional OSINT workflows;
- useful design ideas from the MIT-licensed `mtjikuzu/hermes-osint-skill`, especially fuzzy input handling, company/person/vendor modes, and structured reporting;
- the official Hermes pattern of keeping public-records/entity-resolution and domain-intelligence work in specialized skills/modules.

## Safety / Scope

Default to public, passive, and lawful sources. Do not:
- bypass authentication or access controls;
- test credentials;
- exploit vulnerabilities;
- access stolen/non-public datasets;
- perform intrusive scanning without explicit authorization;
- expose sensitive personal data that is not necessary for the stated investigation purpose.

If authorization is unclear, stay passive.

## Core Evidence Rules

1. Observation is not attribution.
2. One indicator is not a relationship conclusion.
3. Shared infrastructure is weak evidence unless independently corroborated.
4. Every material finding needs provenance: source, query, timestamp, raw/reference artifact.
5. Separate `OBSERVATION`, `INFERENCE`, `UNKNOWN`, and `ALTERNATIVE_EXPLANATION`.
6. Prefer 2+ independent corroborating sources for material conclusions.
7. Tag contradictory evidence; do not hide it.
8. Treat historical continuity as first-class evidence.
9. Do not turn a confidence label into certainty.
10. Make the path from source -> evidence -> finding reproducible.

## Router

Choose the smallest set of modules that answers the question.

| Input / objective | Primary module | Optional follow-on |
|---|---|---|
| Domain, URL, IP, certificate, DNS question | `modules/domain/SKILL.md` | company, username |
| Company, legal entity, ownership, reputation, filings | `modules/company/SKILL.md` | domain, vendor |
| Public professional identity verification | `modules/person/SKILL.md` | username, company |
| Username/handle correlation | `modules/username/SKILL.md` | person |
| Third-party/vendor cyber risk | `modules/vendor/SKILL.md` | domain, company |

Do not load every module unless the case genuinely requires it.

## Initial Classification

Before any search, classify the seed:

- `EXACT_VERIFIED` - confirmed domain, exact legal entity, known public handle.
- `PARTIAL` - partial name, brand name, incomplete company name.
- `AMBIGUOUS` - common name, transliteration, nickname, possible typo.
- `SINGLE_PIVOT` - only one artifact exists (domain/email/username/company).

Then choose one of three search modes:

- `DIRECT` - exact query, narrow scope.
- `FUZZY` - generate controlled variants, then verify candidates.
- `PIVOT` - move from the seed artifact to adjacent evidence types.

Read `references/fuzzy-pivots.md` when input is incomplete or ambiguous.

## Relationship Confidence

Use relationship confidence, not "owner certainty".

- `CONFIRMED`: 2+ independent high-quality sources agree and no material contradiction exists.
- `PROBABLE`: one strong source plus independent supporting evidence, or 2 sources with minor inconsistencies.
- `POSSIBLE`: plausible relationship with limited corroboration.
- `UNVERIFIED`: lead only; needs additional evidence.
- `DISCONFIRMED`: candidate relationship contradicted by stronger evidence.

For technical signals, also record `signal_strength`: `weak`, `moderate`, `strong`.
See `references/confidence-model.md`.

## Case Structure

Every investigation should create or maintain:

```text
cases/CASE-YYYY-MM-DD-XXXXXX/
  case.yaml
  evidence.jsonl
  findings.yaml
  raw/
  screenshots/
  graph.mmd
  report.md
```

For domain cases, the bundled runner can create most of this automatically:

```bash
python3 bin/domain_osint.py example.com
```


## Canonical Runner Enforcement (v1.3.8)

For a domain investigation, the installed runner is the execution engine. **Do not recreate, rewrite, patch, substitute, or wrap the investigation logic in a new Python script unless the user explicitly asks to modify the code.**

Mandatory execution path:

```bash
python3 bin/domain_osint.py <domain>
```

When the skill is installed, prefer the exact installed path:

```bash
python3 ~/.hermes/skills/research/osint-hybrid-investigation/bin/domain_osint.py <domain>
```

Rules:
- Load the relevant module documentation, then invoke the canonical runner.
- Do not create `/tmp/investigate_*.py`, ad-hoc collectors, or replacement runners.
- Do not patch `bin/domain_osint.py` during an investigation.
- If the runner errors, capture the error and report it; do not silently replace the engine.
- Code modification is allowed only when the user explicitly asks to update/debug the skill.
- After execution, analyze the generated `report.md`, `case.yaml`, and `evidence.jsonl`; the model's job is analysis, not reimplementation of collection.

Each v1.3.8 case records the runner version, resolved runner path, SHA-256, and execution mode so an analyst can verify which engine actually produced the artifacts.

## Cross-Module Handoff Contract

When one module hands an artifact to another, use:

```yaml
artifact:
  type: domain|company|username|email|ip|certificate|person
  value: example.com
  source_evidence_ids: [CASE-...-E0001]
  reason_for_pivot: "Observed in authoritative/public source"
  confidence: probable
  restrictions:
    - passive-public
```

Never hand off a speculative value without marking it speculative.

## Report Modes

Use the template in `templates/report-template.md` and choose one output depth:

- `EXECUTIVE`: concise findings, risk/uncertainty, next steps.
- `ANALYST`: evidence table, pivots, contradictions, timeline, confidence.
- `TECHNICAL`: raw technical relationships, infrastructure details, provenance.

## Stop Conditions

Stop or narrow when:
- the investigative question is answered;
- new pivots only repeat shared/CDN infrastructure;
- 1-3 high-confidence candidates remain and have 2+ corroborating points each;
- expanding produces mostly false positives;
- the next step would require intrusive/non-public access;
- source quality is too poor to support further inference.

## Verification Before Finalizing

Confirm that:
- each major conclusion maps to evidence IDs;
- source timestamps are recorded;
- shared-host/CDN false positives are called out;
- person/company identity candidates are not merged on name similarity alone;
- contradictory evidence is represented;
- the report clearly says what remains unknown.


## Current vs Historical Guardrail (v1.3.4)
- crt.sh and Wayback are historical/public observations. Never call a hostname active from CT alone.
- Use live-tls observations for current HTTPS state.
- Report CURRENT STATE, HISTORICAL STATE, and UNVERIFIED LEADS separately.
- urlscan may be public/unauthenticated; note mode in case metadata. Hunt.io and Shodan may be unavailable until configured.


## v1.3.4 source coverage requirement

Every domain investigation must inspect the runner's Source Capability Matrix before interpreting
missing evidence. Distinguish:
- credential absent,
- credential present but endpoint/plan limited,
- rate limited,
- source deliberately skipped to avoid shared-infrastructure false positives,
- source successfully queried but returned no result.

Never convert an unavailable or limited source into a negative finding. Report Core methodology
coverage separately from Optional enrichment coverage.


## Credential isolation (v1.3.5)

For domain enrichment, prefer `~/.osint_keys` with mode `600`. Do not instruct the user to source API secrets into the shell that launches Hermes. The domain runner loads whitelisted credentials inside its own process, reports only presence/source/runtime status, and must never echo credential values. Environment variables are supported for explicit operator use and take precedence over the local credential file.

## Runtime fault isolation (v1.3.8)

- Treat `bin/domain_osint.py` as the canonical execution engine.
- Never patch, rewrite, substitute, or generate a replacement investigation script during a normal case run.
- Never delete `cases/`, prior case directories, raw artifacts, or reports as a recovery step.
- A failure in one source (for example urlscan, Netlas, Censys, VirusTotal, or Shodan) is recorded as that adapter's `ERROR`, while remaining adapters continue.
- The runner persists partial case artifacts even after an isolated adapter failure or user interruption.
- Debugging or modifying the runner is a separate development task and requires an explicit user request; do not mix code repair with evidence collection.


## Analyst interpretation guardrails (v1.3.8)

When summarizing a domain case:
- Never label a nameserver/CDN provider as the registrar. `Registrar` requires an explicit registrar field from registry RDAP/WHOIS or clearly labeled third-party registrar metadata. Cloudflare NS means DNS/proxy provider context only.
- Split certificate reporting into `historical CT issuance`, `latest observed issuance`, and `live TLS`. CT-only evidence must never be described as `active`.
- Prefer `recent certificate issuance activity observed`; `ongoing operation` requires independent current-state DNS/TLS/HTTP evidence.
- Treat VirusTotal engine counts as one aggregated reputation context source, not many independent corroborations.
- Treat urlscan IP diversity as ambiguous by default: it may reflect redirects, CDNs, shared hosting, third-party resources, or real infrastructure changes. Do not claim migration from IP count alone.
- When evidence conflicts (for example CT suggests recent issuance but live TLS is unavailable), report the conflict explicitly instead of choosing the stronger-sounding interpretation.

## v1.3.9 quality rules

When interpreting normalized domain evidence, apply these rules literally:

1. **WHOIS / registry field semantics**
   - `Registry lookup source` describes where registration data came from (for example local WHOIS fallback).
   - `Registrar` is only a registrar value explicitly parsed from RDAP/WHOIS or clearly labeled third-party registrar metadata.
   - `Registry`, `registrar`, `registrant/holder`, `DNS provider`, and `nameserver provider` are different concepts and must not be merged.

2. **Certificate wording**
   - CT rows describe historical issuance, never service liveness.
   - Say `recent certificate issuance activity observed`, not `actively using certificates` or `ongoing operation`, unless live DNS/TLS/HTTP independently confirms current service.
   - If live TLS fails while CT has recent issuance, state the conflict explicitly.

3. **VirusTotal schema discipline**
   - Report `last_analysis_stats` categories exactly as returned.
   - If a denominator is needed, use `engine_total = sum(last_analysis_stats values)` from the runner metrics.
   - `undetected` means no detection verdict from those engines; it does **not** mean benign/harmless and does not imply false positives.
   - Engine verdict counts are one aggregated vendor context source, not independent corroboration.

4. **Historical path/content interpretation**
   - urlscan/archives may show historical paths or strings such as `cardchecker.php`, `bitcoin`, or other suggestive names.
   - Report the literal historical observation first.
   - Any characterization such as fraud, phishing, blackhat service, criminal use, or abuse requires independent corroboration and must otherwise remain an `UNVERIFIED INTERPRETATION`.

5. **Historical IP diversity**
   - Multiple IPs/ASNs may reflect redirects, embedded third-party resources, shared hosting, CDNs/proxies, subdomain separation, or real hosting changes.
   - Do not claim migration or operator movement from IP diversity alone.
