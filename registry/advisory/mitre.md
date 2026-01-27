---
type: advisory
namespace: mitre
full_name: "MITRE Corporation"
operator: "secid:entity/mitre"
website: "https://www.mitre.org"
status: active

sources:
  cve:
    full_name: "Common Vulnerabilities and Exposures"
    urls:
      website: "https://www.cve.org"
      api: "https://cveawg.mitre.org/api"
      bulk_data: "https://github.com/CVEProject/cvelistV5"
      lookup: "https://www.cve.org/CVERecord?id={id}"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/mitre/cve#CVE-2024-1234"
      - "secid:advisory/mitre/cve#CVE-2023-44487"
      - "secid:advisory/mitre/cve#CVE-2021-44228"
---

# MITRE Advisory Sources

MITRE is a US nonprofit organization that operates federally funded research and development centers (FFRDCs). In cybersecurity, MITRE is best known for creating and maintaining foundational security frameworks and databases.

## Why MITRE Matters

MITRE created and operates many of the canonical security identifier systems:

- **CVE (Common Vulnerabilities and Exposures)** - The global standard for vulnerability identification
- **CWE (Common Weakness Enumeration)** - Taxonomy of software/hardware weaknesses
- **ATT&CK** - Framework for adversary tactics, techniques, and procedures
- **CAPEC** - Common Attack Pattern Enumeration and Classification
- **ATLAS** - Adversarial Threat Landscape for AI Systems

When you see a CVE ID, CWE number, or ATT&CK technique - that's MITRE's work.

## Relationship to Other Organizations

- **CISA** contracts MITRE to operate the CVE Program
- **NVD (NIST)** enriches CVE records with CVSS, CPE, CWE data
- **CNAs (CVE Numbering Authorities)** can assign CVE IDs under MITRE's program

---

## cve

The canonical vulnerability identifier system, operated by MITRE.

### Format

```
secid:advisory/mitre/cve#CVE-YYYY-NNNNN
```

### Resolution

```
https://www.cve.org/CVERecord?id={id}
https://cveawg.mitre.org/api/cve/{id}
```

### Notes

- CVE is the canonical identifier - other advisories reference CVEs
- NVD enriches CVE records with CVSS, CPE, CWE
- Quality of descriptions varies by CNA
- MITRE operates the CVE program under contract with CISA
