---
name: company-osint
version: 1.3.0
description: Evidence-first public-source company due diligence and entity-resolution workflow. Verifies legal identity, public filings, ownership/control signals, reputation, operations, and digital footprint without conflating brand names with legal entities.
platforms: [linux, macos, windows]
---

# Company OSINT Module

## Use when
- verifying a company or brand;
- mapping legal entity vs trading name;
- researching ownership/control, filings, public enforcement, reputation, or operations;
- linking a company to domains or public technical infrastructure.

## Workflow

1. **Seed validation** - exact legal name, jurisdiction, registration number if known, brand/domain aliases.
2. **Legal identity** - authoritative registry/filing sources first.
3. **Ownership and officers** - directors/officers/parent/subsidiary links when publicly available.
4. **Financial/public filings** - SEC or equivalent public filings where applicable.
5. **Regulatory/legal** - public regulator actions and court records relevant to the stated objective.
6. **Reputation/media** - reputable news and primary-source statements; separate allegation from established fact.
7. **Operations** - public locations, products, services, major public partnerships/suppliers when relevant.
8. **Digital footprint** - hand off validated domains to `../domain/SKILL.md`.
9. **Network correlation** - related entities only after entity-resolution checks.
10. **Report** - evidence-backed findings, contradictions, unknowns.

## Entity-resolution rules

Never merge records on name similarity alone. Prefer combinations such as:
- legal name + jurisdiction;
- registration number;
- legal name + officer + address;
- company domain + authoritative corporate page/filing;
- historical name/rebrand documented in authoritative/public sources.

Track candidates as `candidate`, `corroborated`, `rejected`, `unresolved`.

## Fuzzy company search

Read `../../references/fuzzy-pivots.md` when a brand/legal-name mismatch, transliteration, rebrand, or incomplete name is present.

## Output fields

At minimum:
- legal entity and jurisdiction;
- confirmed aliases/trading names;
- authoritative identifiers;
- officers/ownership signals where public;
- relevant public legal/regulatory findings;
- validated domains;
- contradictions and unknowns;
- evidence IDs supporting each material finding.
