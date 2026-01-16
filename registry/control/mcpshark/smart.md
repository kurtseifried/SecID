---
type: control
namespace: mcpshark
name: smart
full_name: "Smart Scan Security Controls"
operator: "secid:entity/mcpshark"

urls:
  website: "https://smart.mcpshark.sh"
  index: "https://smart.mcpshark.sh"
  docs: "https://smart.mcpshark.sh/docs"

id_pattern: "[a-z-]+"

examples:
  - "secid:control/mcpshark/smart#agent-analysis"
  - "secid:control/mcpshark/smart#privilege-escalation-detection"
  - "secid:control/mcpshark/smart#owasp-mapping"

status: active
---

# Smart Scan Security Controls

Security checks and analysis capabilities provided by Smart Scan for MCP servers and AI agents.

## Format

```
secid:control/mcpshark/smart#CAPABILITY
secid:control/mcpshark/smart#agent-analysis
secid:control/mcpshark/smart#owasp-mapping
```

## Core Security Controls

### Agent Analysis

| Control | Description |
|---------|-------------|
| `agent-analysis` | Comprehensive AI agent security assessment |
| `tool-analysis` | Analysis of tools exposed by agents |
| `resource-analysis` | Evaluation of resource access patterns |
| `prompt-analysis` | Detection of prompt injection vulnerabilities |
| `capability-analysis` | Assessment of agent capabilities and permissions |

### Vulnerability Detection

| Control | Description |
|---------|-------------|
| `privilege-escalation-detection` | Identifies privilege escalation paths |
| `excessive-agency-detection` | Detects overly broad agent permissions |
| `data-exposure-detection` | Finds sensitive data exposure risks |
| `injection-detection` | Identifies injection vulnerabilities |

### OWASP Mapping

| Control | Description |
|---------|-------------|
| `owasp-mapping` | Maps findings to OWASP LLM Top 10 2025 |
| `owasp-llm01-check` | Prompt Injection detection |
| `owasp-llm02-check` | Sensitive Information Disclosure detection |
| `owasp-llm06-check` | Excessive Agency detection |

### Topology & Visualization

| Control | Description |
|---------|-------------|
| `agent-topology` | Maps agent relationships and dependencies |
| `severity-distribution` | Categorizes findings by severity |
| `attack-path-analysis` | Visualizes potential attack paths |

## OWASP LLM Top 10 Coverage

Smart Scan maps findings to these OWASP categories:

| OWASP ID | Risk | Smart Scan Detection |
|----------|------|---------------------|
| LLM01 | Prompt Injection | Prompt analysis, injection patterns |
| LLM02 | Sensitive Information Disclosure | Data exposure scanning |
| LLM03 | Supply Chain | Dependency analysis |
| LLM06 | Excessive Agency | Permission and capability review |
| LLM07 | System Prompt Leakage | Prompt security analysis |

## Relationship to Entity

The tool itself is documented at:
```
secid:entity/mcpshark/smart
```

This control file documents what security checks the tool provides.

## Integration Controls

| Control | Description |
|---------|-------------|
| `ci-cd-gate` | Pass/fail gates for CI/CD pipelines |
| `api-scanning` | Programmatic scanning via REST API |
| `cli-scanning` | Command-line scanning capability |
| `continuous-monitoring` | Ongoing security assessment |

## Notes

- Controls represent security checks the tool performs
- Findings link to OWASP LLM Top 10 for remediation guidance
- Useful for establishing MCP server security baselines
- Can enforce security gates in deployment pipelines
