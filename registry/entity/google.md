---

type: "entity"
namespace: "google"

common_name: "Google"
full_name: "Google LLC"

urls:
  website: "https://www.google.com"
  security: "https://security.google"

names:
  osv:
    full_name: "Open Source Vulnerabilities"
    urls:
      website: "https://osv.dev"
      api: "https://api.osv.dev"
      github: "https://github.com/google/osv.dev"
    issues_type: "advisory"
    issues_namespace: "osv"

wikidata: "Q95"
status: "active"
established: 1998
---


# Google

Google operates several security initiatives including:

- **OSV** - Open Source Vulnerabilities database
- **Project Zero** - Security research team
- **oss-fuzz** - Continuous fuzzing for open source

## Names in This Namespace

| Name | Full Name | Identifier Type |
|------|-----------|-----------------|
| `osv` | Open Source Vulnerabilities | `advisory/osv/*` |

## Examples

```
secid:entity/google/osv     # The OSV system
```
