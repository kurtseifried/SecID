---
namespace: acm
full_name: "ACM Digital Library"
type: reference

urls:
  website: "https://dl.acm.org"
  lookup: "https://dl.acm.org/doi/{id}"

id_pattern: "10\\.1145/\\d+\\.\\d+"
examples:
  - "10.1145/3319535.3354229"
  - "10.1145/3548606.3560601"

status: draft
---

# ACM Digital Library Namespace

ACM Digital Library - major publisher of computer science research, including top security conferences.

## Format

```
secid:reference/acm/{doi-suffix}
secid:reference/acm/10.1145/3319535.3354229
```

Note: ACM uses DOIs starting with `10.1145/`. The full DOI can also be referenced via `secid:reference/doi/10.1145/...`

## Resolution

```
https://dl.acm.org/doi/{id}
```

## Security-Relevant Venues

| Venue | Description |
|-------|-------------|
| ACM CCS | ACM Conference on Computer and Communications Security |
| ACM ASIA CCS | ACM Asia Conference on Computer and Communications Security |
| ACM TOPS | ACM Transactions on Privacy and Security |
| ACM WiSec | ACM Conference on Security and Privacy in Wireless and Mobile Networks |

## Notes

- ACM DOIs follow pattern: 10.1145/proceeding.paper
- Many papers behind paywall; some open access
- ACM Author-izer provides free access links
- Equivalence with DOI namespace belongs in relationship layer
