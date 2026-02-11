---

type: "entity"
namespace: "github.com"

common_name: "GitHub"
full_name: "GitHub, Inc."

urls:
  website: "https://github.com"
  security: "https://github.com/security"

names:
  ghsa:
    full_name: "GitHub Security Advisories"
    urls:
      website: "https://github.com/advisories"
      api: "https://docs.github.com/en/rest/security-advisories"
      bulk_data: "https://github.com/github/advisory-database"
    issues_type: "advisory"
    issues_namespace: "ghsa"

wikidata: "Q364"
status: "active"
established: 2008
---


# GitHub

GitHub is a platform for software development and version control. In security, GitHub provides:

- **GHSA** - GitHub Security Advisories database
- **Dependabot** - Automated dependency security updates
- **Code scanning** - Security vulnerability detection

## Names in This Namespace

| Name | Full Name | Identifier Type |
|------|-----------|-----------------|
| `ghsa` | GitHub Security Advisories | `advisory/ghsa/*` |

## Examples

```
secid:entity/github.com/ghsa    # The GHSA system
```
