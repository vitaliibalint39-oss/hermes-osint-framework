---
name: username-osint
version: 1.3.0
description: Public username/handle discovery and correlation module with false-positive controls. Uses Sherlock/Maigret-style public profile discovery when locally available, but does not equate handle reuse with identity by itself.
platforms: [linux, macos, windows]
---

# Username OSINT Module

## Core rule

A matching username is a **candidate link**, not proof of common identity.

## Workflow

1. Validate the seed username and context.
2. Search public profiles with available tools (e.g. Sherlock/Maigret) or browser search.
3. Record profile URL, platform, retrieval time, and visible public context.
4. Corroborate with non-sensitive public attributes such as consistent public bio, project/site link, professional role, or explicitly cross-linked accounts.
5. Reject matches that conflict materially.
6. Hand off a corroborated public identity candidate to `../person/SKILL.md` only if needed.

## False-positive controls

Reduce confidence for:
- short/common handles;
- inactive placeholder accounts;
- platform-generated pages that do not prove account existence;
- inconsistent language/region/professional context;
- no cross-link or corroborating public attribute.

## Optional local tools

```bash
sherlock <username>
maigret <username>
```

Use tool output as discovery leads, then verify on the public source page when possible.
