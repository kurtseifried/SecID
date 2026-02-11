---
type: advisory
namespace: pypi.org
full_name: "Python Package Index (PyPA)"
operator: "secid:entity/pypa"
website: "https://pypi.org"
status: active

sources:
  advisory-db:
    full_name: "Python Advisory Database"
    urls:
      website: "https://github.com/pypa/advisory-database"
      bulk_data: "https://github.com/pypa/advisory-database"
      lookup: "https://osv.dev/vulnerability/{id}"
    id_pattern: "PYSEC-\\d{4}-\\d+"
    examples:
      - "secid:advisory/pypi.org/advisory-db#PYSEC-2024-1"
      - "secid:advisory/pypi.org/advisory-db#PYSEC-2023-100"
---

# PyPI Advisory Sources

PyPI is the official package repository for Python, hosting over 500,000 packages. The Python Packaging Authority (PyPA) maintains the Python Advisory Database for security vulnerabilities in Python packages.

## Why PyPI Matters for Security

Python is everywhere:

- **Security tools** - Most security tools are written in Python
- **AI/ML** - PyTorch, TensorFlow, scikit-learn, etc.
- **Web frameworks** - Django, Flask, FastAPI
- **Automation** - Ansible, scripts, data pipelines

Python package vulnerabilities affect security tools, AI systems, and web applications.

## PYSEC ID Format

Python advisories use PYSEC prefix:
```
PYSEC-2024-1    (year 2024, advisory 1)
PYSEC-2023-100  (year 2023, advisory 100)
```

## Relationship to OSV

PyPI advisories are indexed in Google's OSV database:
```
https://osv.dev/vulnerability/PYSEC-2024-1
```

The Python Advisory Database uses OSV schema for interoperability.

## Tooling

- **pip-audit** - Scan installed packages for vulnerabilities
- **Safety** - Commercial Python vulnerability scanner
- **pip** - pip itself can warn about known vulnerabilities

## Notes

- PyPA maintains the advisory database at github.com/pypa/advisory-database
- Many Python packages have native dependencies (C libraries) with their own vulnerabilities
- AI/ML security is increasingly important given Python's dominance in that space

---

## advisory-db

Official vulnerability database for Python packages, maintained by the Python Packaging Authority (PyPA).

### Format

```
secid:advisory/pypi.org/advisory-db#PYSEC-YYYY-NNN
```

### Resolution

Python advisories are indexed in OSV:
```
https://osv.dev/vulnerability/{id}
```

### Why PyPI Advisory DB Matters

Python is ubiquitous in security, data science, and web development:
- **Security tooling** - Most security tools written in Python
- **AI/ML ecosystem** - PyTorch, TensorFlow, etc.
- **pip audit** - Built-in vulnerability checking
- **OSV format** - Machine-readable, standard schema

### Related Sources

- **OSV** - Primary index for PYSEC advisories
- **Safety DB** - Commercial Python vulnerability data
- **Snyk** - Additional Python coverage

### Notes

- PYSEC IDs follow the OSV schema
- Advisories often cross-reference CVEs
- pip-audit tool checks installed packages
- Critical for AI/ML security given Python's dominance
