---
namespace: mcpshark
full_name: "MCPShark"
website: "https://mcpshark.sh"
type: security-vendor
---

# MCPShark (Control Namespace)

Security controls and checks provided by MCPShark tools for MCP server and AI agent security.

## Why MCPShark Controls Matter

MCPShark provides actionable security controls for AI agent ecosystems:

- **Automated scanning** - Checks that can run in CI/CD
- **OWASP mapping** - Industry-standard categorization
- **Privilege analysis** - Detects excessive permissions
- **Agent topology** - Visualizes security relationships

## Control Sources in This Namespace

| Name | Description | Example Controls |
|------|-------------|------------------|
| `smart` | Smart Scan security checks | agent-analysis, owasp-mapping |

## Control Categories

| Category | Purpose |
|----------|---------|
| Analysis | Agent, tool, resource, prompt analysis |
| Detection | Vulnerability and risk detection |
| OWASP | Mapping to LLM Top 10 categories |
| Visualization | Topology and attack path analysis |

## Relationship to Entity

The tools themselves are documented in entity:
```
secid:entity/mcpshark/smart  → What the tool is
secid:control/mcpshark/smart → What security checks it provides
```

## Notes

- Controls represent security capabilities, not requirements
- Can be used to validate MCP server security posture
- Maps findings to OWASP for remediation guidance
