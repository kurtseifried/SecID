---
namespace: pypi
full_name: "Python Package Index (PyPA)"
website: "https://pypi.org"
type: opensource
founded: 2003
operator: "Python Packaging Authority (PyPA)"
---

# Python Package Index (PyPI)

PyPI is the official package repository for Python, hosting over 500,000 packages. The Python Packaging Authority (PyPA) maintains the Python Advisory Database for security vulnerabilities in Python packages.

## Why PyPI Matters for Security

Python is everywhere:

- **Security tools** - Most security tools are written in Python
- **AI/ML** - PyTorch, TensorFlow, scikit-learn, etc.
- **Web frameworks** - Django, Flask, FastAPI
- **Automation** - Ansible, scripts, data pipelines

Python package vulnerabilities affect security tools, AI systems, and web applications.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `advisory-db` | Python Advisory Database | PYSEC-2024-1 |

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
