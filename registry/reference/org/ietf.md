---
namespace: ietf.org
full_name: "Internet Engineering Task Force"
type: reference

urls:
  website: "https://www.ietf.org"
  lookup: "https://www.rfc-editor.org/info/rfc{id}"
  datatracker: "https://datatracker.ietf.org/doc/rfc{id}/"

id_pattern: "\\d+"
examples:
  - "9110"
  - "8446"
  - "6749"

status: draft
---

# IETF Namespace

IETF Request for Comments (RFCs) - Internet standards and protocol specifications.

## Format

```
secid:reference/ietf.org/{rfc-number}
secid:reference/ietf.org/9110
```

Note: Use the RFC number without the "RFC" prefix.

## Resolution

```
https://www.rfc-editor.org/info/rfc{id}
https://datatracker.ietf.org/doc/rfc{id}/
```

## Security-Relevant RFCs

| RFC | Title |
|-----|-------|
| 8446 | TLS 1.3 |
| 6749 | OAuth 2.0 |
| 7519 | JSON Web Token (JWT) |
| 9110 | HTTP Semantics |
| 4251 | SSH Protocol Architecture |

## Notes

- RFCs are immutable once published
- Updates and errata tracked separately
- Some RFCs are informational, some are standards track
- Draft documents use different identifiers (draft-ietf-*)
