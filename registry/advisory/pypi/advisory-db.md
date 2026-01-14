---
type: advisory
namespace: pypi
name: advisory-db
full_name: "Python Advisory Database"
operator: "secid:entity/pypa"

urls:
  website: "https://github.com/pypa/advisory-database"
  bulk_data: "https://github.com/pypa/advisory-database"
  lookup: "https://osv.dev/vulnerability/{id}"

id_pattern: "PYSEC-\\d{4}-\\d+"
examples:
  - "secid:advisory/pypi/advisory-db#PYSEC-2024-1"
  - "secid:advisory/pypi/advisory-db#PYSEC-2023-100"

status: active
---

# Python Advisory Database

Official vulnerability database for Python packages, maintained by the Python Packaging Authority (PyPA).

## Format

```
secid:advisory/pypi/advisory-db#PYSEC-YYYY-NNN
```

## Resolution

Python advisories are indexed in OSV:
```
https://osv.dev/vulnerability/{id}
```

## Why PyPI Advisory DB Matters

Python is ubiquitous in security, data science, and web development:
- **Security tooling** - Most security tools written in Python
- **AI/ML ecosystem** - PyTorch, TensorFlow, etc.
- **pip audit** - Built-in vulnerability checking
- **OSV format** - Machine-readable, standard schema

## Related Sources

- **OSV** - Primary index for PYSEC advisories
- **Safety DB** - Commercial Python vulnerability data
- **Snyk** - Additional Python coverage

## Notes

- PYSEC IDs follow the OSV schema
- Advisories often cross-reference CVEs
- pip-audit tool checks installed packages
- Critical for AI/ML security given Python's dominance
