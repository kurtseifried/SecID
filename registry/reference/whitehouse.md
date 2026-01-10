---
namespace: whitehouse
full_name: "White House / Executive Branch"
type: reference

urls:
  website: "https://www.whitehouse.gov"
  briefing_room: "https://www.whitehouse.gov/briefing-room/"
  omb: "https://www.whitehouse.gov/omb/"

id_patterns:
  - pattern: "eo-\\d{5}"
    type: "executive-order"
    description: "Executive Orders"
  - pattern: "m-\\d{2}-\\d{2}"
    type: "omb-memo"
    description: "OMB Memoranda"
  - pattern: "nsm-\\d+"
    type: "national-security-memo"
    description: "National Security Memoranda"
  - pattern: "ncs-\\d{4}"
    type: "strategy"
    description: "National Strategies"

examples:
  - "eo-14110"
  - "eo-14028"
  - "m-24-10"
  - "nsm-22"
  - "ncs-2023"

status: active
---

# White House Namespace

US Executive Branch publications and policy documents.

## Format

```
secid:reference/whitehouse/{id}
secid:reference/whitehouse/eo-14110
```

## Document Types

| Pattern | Type | Example |
|---------|------|---------|
| `eo-NNNNN` | Executive Order | eo-14110 (AI), eo-14028 (Cyber) |
| `m-NN-NN` | OMB Memo | m-24-10 (AI Governance) |
| `nsm-NN` | National Security Memo | nsm-22 (Critical Infrastructure) |
| `ncs-YYYY` | National Strategy | ncs-2023 (Cybersecurity Strategy) |

## Key Documents

| ID | Title |
|----|-------|
| eo-14110 | Safe, Secure, and Trustworthy AI |
| eo-14028 | Improving the Nation's Cybersecurity |
| m-24-10 | Advancing AI Governance |
| nsm-22 | Critical Infrastructure Security |
| ncs-2023 | National Cybersecurity Strategy |

## Subpaths

```
secid:reference/whitehouse/eo-14110#section-4.1
secid:reference/whitehouse/eo-14110#section-4.2
```

## Relationships

```
reference/whitehouse/eo-14110 → precedes → regulation/us/ai-...
reference/whitehouse/m-24-10 → implements → reference/whitehouse/eo-14110
```

## Notes

- EOs have force of law but can be revoked
- NSMs for classified/national security matters
- OMB memos guide federal agency implementation
