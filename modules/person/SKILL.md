---
name: public-identity-osint
version: 1.3.0
description: Public-source professional identity verification for lawful due diligence. Uses controlled candidate generation, corroboration, and privacy minimization; avoids intrusive personal-data aggregation.
platforms: [linux, macos, windows]
---

# Public Identity Verification Module

## Use when
- verifying a public/professional identity claim;
- confirming public employment, board roles, publications, professional licenses, or public affiliations;
- resolving whether public records/profiles refer to the same person.

## Do not use for
- stalking, doxxing, locating a private person, or compiling unnecessary sensitive personal information;
- private contact-data discovery unrelated to a legitimate stated objective;
- accessing stolen/leaked personal datasets.

## Workflow

1. Define the legitimate verification question.
2. Record only known seed attributes necessary for disambiguation.
3. Generate limited variants if spelling/transliteration is uncertain.
4. Search authoritative/professional sources first.
5. Cluster candidates by non-sensitive public attributes (employer, role, city/region, publication, organization).
6. Hand off public usernames to `../username/SKILL.md` only when relevant.
7. Require at least two corroborating attributes before treating two public records as the same person when the name is common.
8. Record rejected candidates and contradictions.
9. Minimize personal data in the final report.

## Confidence

Use `CONFIRMED / PROBABLE / POSSIBLE / UNVERIFIED / DISCONFIRMED` from `../../references/confidence-model.md`.

## Output

Report only information relevant to the objective. Distinguish public professional facts from inference and omit unnecessary private/sensitive details.
