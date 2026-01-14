---
namespace: atlassian
full_name: "Atlassian Corporation"
website: "https://www.atlassian.com"
type: corporation
founded: 2002
headquarters: "Sydney, Australia"
---

# Atlassian Corporation

Atlassian is an Australian software company producing collaboration and development tools including Jira, Confluence, Bitbucket, and Trello. Atlassian products are widely used in enterprises.

## Why Atlassian Matters for Security

Atlassian products are enterprise staples:

- **Confluence** - Wiki and documentation platform
- **Jira** - Issue tracking and project management
- **Bitbucket** - Git repository hosting
- **Bamboo** - CI/CD server
- **Trello** - Project management boards

Confluence in particular has been a high-profile target, with multiple critical RCE vulnerabilities.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `jira-security` | Security Advisories | CVE-2023-22515, CONFSERVER-92475 |

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
