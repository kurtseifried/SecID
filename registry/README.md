# SecID Registry

Namespace definitions for all SecID types. The directory structure mirrors SecID identifiers.

## Structure

```
registry/
├── <type>.md                    # Type description (e.g., advisory.md)
├── <type>/                      # Namespaces for that type
│   └── <namespace>/             # Organization namespace
│       └── <name>.md            # Database/framework definition
...

# Examples:
registry/advisory/mitre/cve.md   → secid:advisory/mitre/cve
registry/weakness/mitre/cwe.md   → secid:weakness/mitre/cwe
registry/ttp/mitre/attack.md     → secid:ttp/mitre/attack
registry/control/nist/csf.md     → secid:control/nist/csf
```

Each type has:
- A **type.md** file at the root describing the type
- A **type/** directory containing namespace subdirectories
- Each namespace directory contains **name.md** files for databases/frameworks

## Types

| Type | Description |
|------|-------------|
| `advisory` | Publications/records about vulnerabilities |
| `weakness` | Abstract flaw patterns |
| `ttp` | Adversary techniques and behaviors |
| `control` | Security requirements and capabilities that implement them |
| `regulation` | Laws and binding legal requirements |
| `entity` | Organizations, products, services, platforms |
| `reference` | Documents, publications, research |

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

The file location `registry/weakness/mitre/cwe.md` corresponds to `secid:weakness/mitre/cwe`.

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
2. Identify the organization (namespace) and what they publish (name)
3. Create `registry/<type>/<namespace>/<name>.md`
4. Fill in the frontmatter with resolution info (urls, id_pattern, examples)
5. Add context in the markdown body (format, resolution rules, notes)

**For security tools:** Consider both entity (what it is) and control (what it checks).

