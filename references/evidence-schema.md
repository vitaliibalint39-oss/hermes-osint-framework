# Unified Evidence Schema

All modules should normalize important observations to the same record shape.

```json
{
  "evidence_id": "CASE-...-E0001",
  "case_id": "CASE-...",
  "source_adapter": "rdap",
  "source_name": "Authoritative RDAP service",
  "source_url": "https://...",
  "query": "example.com",
  "collected_utc": "2026-09-24T14:00:00Z",
  "observed_utc": null,
  "artifact_type": "domain",
  "artifact": "example.com",
  "relationship": "registered_nameserver",
  "observation": "RDAP lists nameserver ns1.example.net",
  "raw_ref": "raw/rdap-example.com.json",
  "signal_strength": "moderate",
  "confidence": "high",
  "notes": ""
}
```

## Required properties

For material evidence, preserve:
- source identity;
- query or retrieval parameters;
- UTC collection time;
- observed/historical time when present;
- exact artifact value;
- relationship type;
- raw/reference location;
- analyst note where interpretation could be ambiguous.

## Finding vs evidence

Evidence records are observations. Findings are analytical statements that cite evidence IDs.
