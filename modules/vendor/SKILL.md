---
name: vendor-risk-osint
version: 1.3.0
description: Public-source third-party/vendor cyber-risk and data-protection due diligence. Separates externally observable facts from vendor claims and contract/compliance questions.
platforms: [linux, macos, windows]
---

# Vendor Risk OSINT Module

## Use when
- evaluating a SaaS/cloud/vendor before integration or data sharing;
- reviewing public security/privacy posture;
- preparing questions for procurement/security/legal review.

## Important boundary

This module is not a legal compliance certification and does not replace SOC 2/ISO reports, DPAs, penetration-test reports, or legal review.

## Workflow

1. **Vendor identity** - hand off legal-entity verification to company module if needed.
2. **Public privacy posture** - privacy policy, DPA availability, subprocessor list, data-residency claims.
3. **Public assurance claims** - SOC 2/ISO/FedRAMP/etc.; mark vendor claims separately from independently verified certificate/register evidence.
4. **Public incident history** - documented breach/security incidents and regulator notices from reliable public sources.
5. **External technical hygiene** - hand validated vendor domains to domain module; keep passive unless explicitly authorized.
6. **Operational resilience claims** - status page/history, published SLA/BCP/DR statements if public.
7. **Contract questions** - identify gaps that need vendor/legal confirmation rather than guessing.
8. **Report** - facts, claims, unanswered questions, and follow-up evidence requests.

## Risk language

Do not assign a categorical "safe/unsafe" verdict from OSINT alone. Use factual findings plus severity/uncertainty for each issue.
