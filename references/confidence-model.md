# Confidence and False-Positive Model

## Two separate dimensions

Record both:

1. `signal_strength` - how distinctive a specific technical/identity signal is.
2. `relationship_confidence` - overall confidence after corroboration and contradictions.

## Typical domain signal strength

| Signal | Default strength | Notes |
|---|---|---|
| Same large shared/CDN IP | weak | Cloudflare/CDNs/shared hosting create many unrelated co-tenants. |
| Same public cloud ASN | weak | Usually only provider-level association. |
| Same generic nameserver provider | weak | Large DNS providers are non-distinctive. |
| Same uncommon/custom NS pair | moderate | Stronger if historical continuity exists. |
| Same custom MX infrastructure | moderate | Distinctiveness depends on provider. |
| Same certificate SAN context | moderate | Stronger for unusual, directly co-listed hostnames. |
| Same unique analytics/tag identifier | strong | Verify reuse and page ownership context. |
| Same unique public contact email across historical pages | strong | Confirm it is not a generic service address. |
| Same public legal entity in authoritative records | strong | Prefer registry/filing evidence. |
| Historical continuity across multiple independent artifacts | strong | Particularly useful for rebrands/migrations. |

## Relationship confidence

### CONFIRMED
- 2+ independent, high-quality sources;
- no material contradiction;
- relationship type is explicit or strongly evidenced.

### PROBABLE
- one authoritative/strong source plus corroboration; or
- multiple independent sources with small inconsistencies.

### POSSIBLE
- plausible, limited corroboration;
- alternative explanations remain credible.

### UNVERIFIED
- lead only;
- insufficient evidence for a finding.

### DISCONFIRMED
- stronger evidence contradicts the candidate relationship.

## False-positive suppressors

Reduce weight when any of these are present:
- CDN/reverse proxy;
- shared hosting;
- public SaaS tenant infrastructure;
- generic email provider;
- common analytics/template code copied across unrelated sites;
- common name without location/employer/date corroboration;
- archive capture from a third-party embedded resource;
- search-engine snippet without source-page confirmation.

## Minimum finding format

```yaml
finding: "Two domains appear technically related"
relationship_confidence: probable
supporting_evidence: [E0004, E0012, E0021]
contradictory_evidence: []
alternative_explanations:
  - "Could be the same managed-service provider"
unknowns:
  - "Common ownership not independently established"
```
