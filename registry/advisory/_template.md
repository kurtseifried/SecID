---
# Identity
namespace: ""
full_name: ""
type: advisory
operator: ""  # e.g., "secid:entity/example" or "secid:entity/example/product"

# Access
urls:
  website: ""
  api: ""
  lookup: ""  # URL template with {id} placeholder

# ID Routing (for namespaces with multiple ID patterns)
id_routing:
  - pattern: ""           # Regex pattern for this ID type
    system: ""            # Human-readable system name
    url: ""               # URL template with {id} placeholder

# Examples
examples: []

status: active  # active, deprecated, historical
---

# [Namespace Name]

[Brief description]

## Format

```
secid:advisory/{namespace}/{id}
```

[Explain ID routing if applicable]

## Resolution

[How to resolve IDs to URLs]

## Notes

[Caveats, special cases, etc.]
