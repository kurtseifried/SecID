---
type: advisory
namespace: embracethered
name: monthofaibugs
full_name: "Month of AI Bugs"
operator: "secid:entity/embracethered"

urls:
  website: "https://monthofaibugs.com"
  index: "https://monthofaibugs.com/#list-of-bugs"
  lookup: "https://monthofaibugs.com/{id}/"

id_pattern: "episode-\\d+"
versions:
  - "2025"

examples:
  - "secid:advisory/embracethered/monthofaibugs#episode-1"
  - "secid:advisory/embracethered/monthofaibugs#episode-15"
  - "secid:advisory/embracethered/monthofaibugs#episode-29"

status: active
---

# Month of AI Bugs

A vulnerability disclosure initiative documenting security bugs in agentic AI systems. August 2025 project by Embrace the Red.

## Format

```
secid:advisory/embracethered/monthofaibugs#episode-N
secid:advisory/embracethered/monthofaibugs#episode-1
secid:advisory/embracethered/monthofaibugs#episode-29
```

## Resolution

Episodes are available at `https://monthofaibugs.com/episode-N/`

## Coverage

29 documented vulnerabilities affecting major AI coding agents:

| Affected System | Examples |
|-----------------|----------|
| ChatGPT | Prompt injection, data exfiltration |
| Claude Code | DNS exfiltration (CVE-2025-55284) |
| GitHub Copilot | RCE (CVE-2025-53773) |
| Google Jules | Various vulnerabilities |
| Cursor | Agent vulnerabilities |
| Windsurf | Agent vulnerabilities |

## Episode Structure

Each episode documents:

| Field | Content |
|-------|---------|
| Vulnerability | Technical description |
| Affected System | Which AI agent(s) |
| Exploitation | How it can be exploited |
| Status | Fixed / In Progress / Unresolved |
| CVE | If assigned |
| Demo | Video or blog post |

## CVEs Assigned

| CVE | Episode | Description |
|-----|---------|-------------|
| CVE-2025-55284 | Claude Code | DNS exfiltration via prompt injection |
| CVE-2025-53773 | GitHub Copilot | Remote code execution |

## Why This Matters

Month of AI Bugs focuses on:

- **Agentic AI risks** - Systems that can take actions
- **Prompt injection** - Primary attack vector
- **Tool abuse** - Exploiting agent capabilities
- **Vendor accountability** - Tracking remediation status

## Relationship to Other Sources

| Source | Relationship |
|--------|--------------|
| CVE/NVD | Some bugs get CVEs assigned |
| OWASP Agentic Top 10 | Real-world examples of ASI risks |
| OWASP AI Exchange | Demonstrates threat categories |

## Notes

- Initiative ran August 2025
- Led by @wunderwuzzi23 (Johann Rehberger)
- "Embrace the Red" research team
- Focus on responsible disclosure
- Highlights vendor responsiveness gaps
