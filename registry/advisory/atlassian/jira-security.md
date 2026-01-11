---
type: advisory
namespace: atlassian
name: jira-security
full_name: "Atlassian Security Advisory"
operator: "secid:entity/atlassian"

urls:
  website: "https://www.atlassian.com/trust/security/advisories"
  jira: "https://jira.atlassian.com/browse/{id}"

id_patterns:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE identifier"
  - pattern: "[A-Z]+-\\d+"
    description: "Jira issue ID"

examples:
  - "secid:advisory/atlassian/jira-security#CVE-2023-22515"
  - "secid:advisory/atlassian/jira-security#CONFSERVER-92475"

status: active
---

# Atlassian Security Advisory

Atlassian product security advisories.

## Format

```
secid:advisory/atlassian/jira-security#CVE-YYYY-NNNN
secid:advisory/atlassian/jira-security#PROJECT-NNNNN
```

Accepts CVE IDs or Jira issue IDs.

## Resolution

```
secid:advisory/atlassian/jira-security#CONFSERVER-92475
  → https://jira.atlassian.com/browse/CONFSERVER-92475
```

## Common Project Keys

| Key | Product |
|-----|---------|
| `CONFSERVER` | Confluence Server/Data Center |
| `JRASERVER` | Jira Server/Data Center |
| `BSERV` | Bitbucket Server |
| `BAM` | Bamboo |

## Notes

- Covers Confluence, Jira, Bitbucket, Bamboo, etc.
- High-profile targets (Confluence RCE vulnerabilities)
- Cloud vs Server/Data Center have different advisory tracks
