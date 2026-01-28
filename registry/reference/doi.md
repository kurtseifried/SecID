---
namespace: doi
full_name: "Digital Object Identifier"
type: reference

urls:
  website: "https://www.doi.org"
  lookup: "https://doi.org/{id}"

id_pattern: "10\\.\\d{4,}/[^\\s]+"
examples:
  - "10.6028/NIST.AI.100-1"
  - "10.48550/arXiv.2303.08774"

status: draft
---

# DOI Namespace

Digital Object Identifiers - persistent identifiers for documents, datasets, and other digital objects.

## Format

```
secid:reference/doi/{doi}
secid:reference/doi/10.6028/NIST.AI.100-1
```

## Resolution

```
https://doi.org/{id}
```

DOI.org provides universal resolution to the current location of the resource.

## Notes

- DOIs are assigned by registration agencies (CrossRef, DataCite, etc.)
- Format: `10.prefix/suffix` where prefix identifies the registrant
- Persistent: DOIs should resolve even if the resource moves
- Many documents have both a DOI and other identifiers (arXiv, ISBN)
- Equivalence between SecIDs (e.g., DOI and arXiv for same paper) belongs in the relationship layer
