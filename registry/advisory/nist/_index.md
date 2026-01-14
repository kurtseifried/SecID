---
namespace: nist
full_name: "National Institute of Standards and Technology"
website: "https://www.nist.gov"
type: government
founded: 1901
headquarters: "Gaithersburg, Maryland, USA"
parent: "US Department of Commerce"
---

# National Institute of Standards and Technology (NIST)

NIST is a US government agency that develops standards, guidelines, and measurements for technology and cybersecurity. In security, NIST is known for the NVD, Cybersecurity Framework, and SP 800 series publications.

## Why NIST Matters

NIST provides authoritative security guidance used worldwide:

- **NVD (National Vulnerability Database)** - Enriches CVE records with CVSS scores, CPE, and CWE mappings
- **NIST Cybersecurity Framework (CSF)** - Widely adopted security framework
- **SP 800 series** - Security guidance documents (800-53, 800-61, etc.)
- **CVSS hosting** - While FIRST owns CVSS, NVD provides CVSS scores

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `nvd` | National Vulnerability Database | CVE-2021-44228 (same ID, enriched data) |

## NVD vs CVE

Both use the same CVE identifiers, but they serve different purposes:

- **CVE (MITRE)** - The canonical vulnerability record (description, references)
- **NVD (NIST)** - Enrichment layer adding CVSS, CPE, CWE, analysis

```
secid:advisory/mitre/cve#CVE-2021-44228   → The CVE record itself
secid:advisory/nist/nvd#CVE-2021-44228    → NVD's enriched view of that CVE
```

## Notes

- NVD had a significant enrichment backlog in 2024; CISA Vulnrichment helps fill gaps
- NIST standards are often mandated for US federal agencies (FISMA)
- Many international organizations adopt NIST frameworks voluntarily
