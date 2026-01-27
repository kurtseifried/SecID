---
type: entity
namespace: mcpshark
full_name: "MCPShark"
operator: "secid:entity/mcpshark"
website: "https://mcpshark.sh"
status: active

sources:
  smart:
    full_name: "Smart Scan - MCP Security Analyzer"
    urls:
      website: "https://smart.mcpshark.sh"
      dashboard: "https://smart.mcpshark.sh/dashboard"
      api: "https://smart.mcpshark.sh/api"
      docs: "https://smart.mcpshark.sh/docs"
---

# MCPShark

Security tooling for the Model Context Protocol (MCP) ecosystem.

## Why MCPShark Matters

As MCP adoption grows, security tooling is essential:

- **First dedicated MCP scanner** - Purpose-built for AI agent security
- **OWASP integration** - Maps to LLM Top 10 standards
- **CI/CD ready** - Integrates into development workflows
- **Comprehensive analysis** - Agents, tools, resources, prompts

## Related Namespaces

| Namespace | Relationship |
|-----------|--------------|
| `secid:control/mcpshark/smart` | Security controls provided by Smart Scan |
| `secid:weakness/owasp/llm-top10` | Vulnerability categories detected |
| `secid:weakness/owasp/agentic-top10` | Agent risks detected |

---

## smart

A comprehensive security analysis tool for Model Context Protocol (MCP) servers and AI agents. Evaluates safety and trustworthiness by analyzing agents, tools, resources, prompts, and capabilities.

### What It Is

Smart Scan is a security scanner purpose-built for the AI agent ecosystem:

| Capability | Description |
|------------|-------------|
| **Smart Agent Analysis** | Analyzes AI agents, tools, resources, prompts, and capabilities |
| **Vulnerability Detection** | Identifies security vulnerabilities and privilege escalation paths |
| **OWASP Mapping** | Maps findings to OWASP LLM Top 10 2025 categories |
| **Topology Visualization** | Interactive agent topology and security dashboards |

### Access Methods

| Method | Use Case |
|--------|----------|
| **Web Dashboard** | Interactive visualization and result browsing |
| **CLI Tool** | Local scanning and CI/CD integration |
| **REST API** | Programmatic scanning and automation |

### CI/CD Integration

Supports integration with:
- GitHub Actions
- GitLab CI
- CircleCI
- Any CI/CD pipeline via CLI or API

### How It Works

1. Sign up and generate API token
2. Submit MCP server or A2A agent card data
3. Receive security analysis with OWASP categorization
4. View results in dashboard with topology visualization

### What It Scans

| Target | Analysis |
|--------|----------|
| MCP Servers | Server configuration, exposed tools, permissions |
| AI Agents | Agent capabilities, tool access, resource scope |
| A2A Agent Cards | Agent-to-agent communication security |
| Prompts | Prompt injection vulnerabilities |

### Security Findings

Findings are categorized by:
- Severity (Critical, High, Medium, Low)
- OWASP LLM Top 10 2025 category
- Actionable remediation recommendations

### Related SecIDs

| Type | SecID | Relationship |
|------|-------|--------------|
| Control | `secid:control/mcpshark/smart` | Security checks performed |
| Weakness | `secid:weakness/owasp/llm-top10` | Mapped vulnerability categories |
| Weakness | `secid:weakness/owasp/agentic-top10` | Agent-specific risks detected |

### Notes

- First dedicated security scanner for MCP ecosystem
- Combines rule-based checks with LLM-powered semantic analysis
- Useful for validating MCP servers before deployment
- Integrates with development workflows
