# SecID Registry

Namespace definitions for all SecID types.

## Structure

```
registry/
├── <type>.md              # Type description (e.g., advisory.md)
├── <type>/                # Namespace files for that type
│   └── <namespace>.md     # Namespace definition
...
```

Each type has:
- A **type.md** file at the root describing the type
- A **type/** directory containing namespace definition files

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
type: "advisory"
namespace: "redhat"
common_name: "Red Hat Security"

urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"

id_routing:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "Red Hat CVE Database"
    url_template: "https://access.redhat.com/security/cve/{id}"
  - pattern: "RHSA-\\d{4}:\\d+"
    system: "Red Hat Security Advisory"
    url_template: "https://access.redhat.com/errata/{id}"

status: "active"
---

# Red Hat Security

[Description and details...]
```

## Contributing

To add a new namespace:
1. Determine which type it belongs to
2. Create `<type>/<namespace>.md`
3. Fill in the frontmatter with resolution info
4. Add context in the markdown body

