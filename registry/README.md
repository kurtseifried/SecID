# SecID Registry

Namespace definitions for all SecID types. The directory structure mirrors SecID identifiers.

## Structure

```
registry/
├── <type>.md                    # Type description (e.g., advisory.md)
├── <type>/                      # Namespaces for that type
│   └── <namespace>.md           # Organization namespace definition
...

# Examples:
registry/advisory/mitre.md   → secid:advisory/mitre/cve, secid:advisory/mitre/nvd
registry/weakness/mitre.md   → secid:weakness/mitre/cwe
registry/ttp/mitre.md        → secid:ttp/mitre/attack, secid:ttp/mitre/atlas
registry/control/nist.md     → secid:control/nist/csf, secid:control/nist/800-53
```

Each type has:
- A **type.md** file at the root describing the type
- A **type/** directory containing namespace files
- Each namespace file defines all databases/frameworks from that organization

## Types

| Type | Description | Also Contains |
|------|-------------|---------------|
| `advisory` | Publications/records about vulnerabilities | Incident reports (AIID, NHTSA, FDA adverse events) |
| `weakness` | Abstract flaw patterns | |
| `ttp` | Adversary techniques and behaviors | |
| `control` | Security requirements and capabilities | Prescriptive benchmarks, documentation standards |
| `regulation` | Laws and binding legal requirements | |
| `entity` | Organizations, products, services, platforms | |
| `reference` | Documents, publications, research | |

**Note:** Some types intentionally contain related concepts (see "Also Contains" column). This allows the spec to evolve based on real usage patterns rather than premature categorization. See DESIGN-DECISIONS.md for the rationale.

## Namespace File Format

Namespace files use YAML frontmatter + Markdown body:

```yaml
---
type: "weakness"
namespace: "mitre"
name: "cwe"
full_name: "Common Weakness Enumeration"
operator: "secid:entity/mitre/cwe"

urls:
  website: "https://cwe.mitre.org"
  lookup: "https://cwe.mitre.org/data/definitions/{num}.html"

id_pattern: "CWE-\\d+"
examples:
  - "secid:weakness/mitre/cwe#CWE-79"
  - "secid:weakness/mitre/cwe#CWE-89"

status: "active"
---

# CWE (MITRE)

The canonical software weakness taxonomy...

## Format

secid:weakness/mitre/cwe#CWE-NNN

## Resolution

https://cwe.mitre.org/data/definitions/{num}.html
```

The file location `registry/weakness/mitre.md` corresponds to `secid:weakness/mitre/*` (all MITRE weakness namespaces like CWE).

## Patterns

### Security Tools: Entity + Control

Security tools that provide security checks should be documented in **both** entity and control:

| Type | Purpose | Example |
|------|---------|---------|
| `entity` | What the tool IS | Product description, capabilities, access methods |
| `control` | What security checks it PROVIDES | Specific checks, detections, mappings |

**Example: MCPShark Smart Scan**

```
secid:entity/mcpshark/smart      → The Smart Scan tool itself
secid:control/mcpshark/smart     → Security checks it provides
```

**Entity file** (`registry/entity/mcpshark/smart.md`):
- What the tool is and does
- CLI, API, Dashboard access methods
- CI/CD integration capabilities
- What it scans (MCP servers, AI agents)

**Control file** (`registry/control/mcpshark/smart.md`):
- `#agent-analysis` - Agent security assessment
- `#privilege-escalation-detection` - Finds escalation paths
- `#owasp-mapping` - Maps findings to OWASP LLM Top 10
- `#agent-topology` - Visualizes security relationships

This pattern applies to any security tool with defined checks:
- Vulnerability scanners (Trivy, Grype, Snyk)
- SAST tools (Semgrep, CodeQL)
- AI/MCP scanners (MCPShark Smart Scan)

### Weakness + Control Pairing

Some frameworks define both weaknesses AND controls (like OWASP AI Exchange):

```
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION  → The threat
secid:control/owasp/ai-exchange#PROMPTINJECTIONIOHANDLING  → The mitigation
```

Document in both types when the source provides both perspectives.

## Contributing

To add a new namespace:
1. Determine which type it belongs to
2. Identify the organization (namespace)
3. Create or update `registry/<type>/<namespace>.md`
4. Fill in the frontmatter with resolution info (urls, id_pattern, examples)
5. Add context in the markdown body (format, resolution rules, notes)

**For security tools:** Consider both entity (what it is) and control (what it checks).

