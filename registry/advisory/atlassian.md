---
type: advisory
namespace: atlassian
full_name: "Atlassian Corporation"
operator: "secid:entity/atlassian"
website: "https://www.atlassian.com"
status: active

sources:
  jira-security:
    full_name: "Atlassian Security Advisory"
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
---

# Atlassian Advisory Sources

Atlassian is an Australian software company producing collaboration and development tools including Jira, Confluence, Bitbucket, and Trello. Atlassian products are widely used in enterprises.

## Why Atlassian Matters for Security

Atlassian products are enterprise staples:

- **Confluence** - Wiki and documentation platform
- **Jira** - Issue tracking and project management
- **Bitbucket** - Git repository hosting
- **Bamboo** - CI/CD server
- **Trello** - Project management boards

Confluence in particular has been a high-profile target, with multiple critical RCE vulnerabilities.

## Advisory Format

Atlassian advisories can be referenced by:
- **CVE ID** - Standard vulnerability identifier
- **Jira Issue ID** - Internal tracking (e.g., CONFSERVER-92475)

## Server/Data Center vs Cloud

Atlassian has two deployment models with different security implications:

- **Cloud** - Atlassian-hosted, Atlassian handles patching
- **Server/Data Center** - Self-hosted, customers must patch

Server/Data Center vulnerabilities are particularly dangerous because customers must act to patch.

## Notable Vulnerabilities

- **CVE-2023-22515** - Confluence privilege escalation (actively exploited)
- **CVE-2022-26134** - Confluence OGNL injection RCE
- **CVE-2021-26084** - Confluence OGNL injection RCE

## Notes

- Atlassian is ending Server products; moving to Cloud/Data Center only
- Confluence RCEs frequently appear in CISA KEV
- Security bulletins released on Tuesdays

---

## jira-security

Atlassian product security advisories.

### Format

```
secid:advisory/atlassian/jira-security#CVE-YYYY-NNNN
secid:advisory/atlassian/jira-security#PROJECT-NNNNN
```

Accepts CVE IDs or Jira issue IDs.

### Resolution

```
secid:advisory/atlassian/jira-security#CONFSERVER-92475
  -> https://jira.atlassian.com/browse/CONFSERVER-92475
```

### Common Project Keys

| Key | Product |
|-----|---------|
| `CONFSERVER` | Confluence Server/Data Center |
| `JRASERVER` | Jira Server/Data Center |
| `BSERV` | Bitbucket Server |
| `BAM` | Bamboo |

### Notes

- Covers Confluence, Jira, Bitbucket, Bamboo, etc.
- High-profile targets (Confluence RCE vulnerabilities)
- Cloud vs Server/Data Center have different advisory tracks
