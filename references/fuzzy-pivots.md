# Fuzzy Search and Pivot Strategy

## Goal

Handle incomplete or ambiguous inputs without letting the search explode into unverified matches.

## Input grading

1. Exact and verified: proceed directly.
2. Partial: generate limited variants.
3. Ambiguous: widen once, cluster candidates, then narrow.
4. Single artifact: pivot only to logically adjacent artifact types.

## Controlled variants

For companies:
- legal suffix variants: LLC, Inc, Ltd, Corp, GmbH, etc.;
- brand/trading name vs legal name;
- punctuation and spacing differences;
- transliteration variants when relevant;
- known former names/rebrands.

For public professional identity verification:
- full name / first+last / initials;
- transliterations;
- known employer, city, role, public handle.

Do **not** use generated variants as facts. They are search candidates only.

## Widen / narrow

Widen if:
- zero results on a verified seed;
- entity has a known rebrand/history;
- transliteration or spelling uncertainty is documented.

Narrow if:
- candidate count exceeds 15;
- a common name is involved;
- there is a known location/employer/domain/date range.

Stop widening around 5-15 candidates. Stop narrowing when 1-3 candidates remain with at least two corroborating attributes each.

## Pivot map

| Seed | Safe public-source pivots |
|---|---|
| Domain | RDAP, DNS, CT, web archive, public company references |
| Company | registry, domain, filings, directors/officers, public news |
| Username | public profiles, reused handle variants, public bio clues |
| Public email | domain, public professional pages, public registration mentions |
| IP | ASN/provider, passive DNS, CT context |
| Certificate | SAN hostnames, validity history, issuer/context |

## Candidate state

Every candidate must be one of:
- `candidate`
- `corroborated`
- `rejected`
- `unresolved`

Never silently drop rejected candidates if they materially explain why a match was ruled out.
