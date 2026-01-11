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

## Contributing

To add a new namespace:
1. Determine which type it belongs to
2. Identify the organization (namespace) and what they publish (name)
3. Create `registry/<type>/<namespace>/<name>.md`
4. Fill in the frontmatter with resolution info (urls, id_pattern, examples)
5. Add context in the markdown body (format, resolution rules, notes)

