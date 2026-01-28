---
namespace: zenodo
full_name: "Zenodo"
type: reference

urls:
  website: "https://zenodo.org"
  lookup: "https://zenodo.org/record/{id}"
  api: "https://zenodo.org/api/records/{id}"

id_pattern: "\\d+"
examples:
  - "7899048"
  - "5711467"

status: draft
---

# Zenodo Namespace

Zenodo - CERN's open-access repository for research data, papers, software, and more.

## Format

```
secid:reference/zenodo/{record-id}
secid:reference/zenodo/7899048
```

## Resolution

```
https://zenodo.org/record/{id}
```

## Notes

- Operated by CERN as part of OpenAIRE
- Accepts any research output: papers, datasets, software, presentations
- DOIs assigned: 10.5281/zenodo.{id}
- Free and open access
- Good for datasets and supplementary materials
- Versioning support with concept DOIs
- GitHub integration for software releases
