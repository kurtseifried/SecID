---

# Namespace definition for entity/mitre
type: "entity"
namespace: "mitre"

# Organization info
common_name: "MITRE"
full_name: "The MITRE Corporation"

urls:
  website: "https://www.mitre.org"

# Names within this namespace and their resolution
names:
  cve:
    full_name: "Common Vulnerabilities and Exposures"
    urls:
      website: "https://www.cve.org"
      api: "https://cveawg.mitre.org/api"
      bulk_data: "https://github.com/CVEProject/cvelistV5"
    # Note: CVE issues advisory identifiers - see advisory/cve namespace
    issues_type: "advisory"
    issues_namespace: "cve"
  cwe:
    full_name: "Common Weakness Enumeration"
    urls:
      website: "https://cwe.mitre.org"
      api: "https://cwe.mitre.org/data/index.html"
    # Note: CWE defines weakness identifiers - see weakness/cwe namespace
    issues_type: "weakness"
    issues_namespace: "cwe"
  attack:
    full_name: "MITRE ATT&CK"
    urls:
      website: "https://attack.mitre.org"
      api: "https://attack.mitre.org/docs/api/"
      github: "https://github.com/mitre-attack/attack-stix-data"
    # Note: ATT&CK defines TTP identifiers - see ttp/attack namespace
    issues_type: "ttp"
    issues_namespace: "attack"
  atlas:
    full_name: "Adversarial Threat Landscape for AI Systems"
    urls:
      website: "https://atlas.mitre.org"
      github: "https://github.com/mitre-atlas/atlas-data"
    # Note: ATLAS defines AI-specific TTP identifiers - see ttp/atlas namespace
    issues_type: "ttp"
    issues_namespace: "atlas"
  capec:
    full_name: "Common Attack Pattern Enumeration and Classification"
    urls:
      website: "https://capec.mitre.org"
    issues_type: "ttp"
    issues_namespace: "capec"

wikidata: "Q1116236"
status: "active"
established: 1958
---


# MITRE

MITRE is a US-based not-for-profit organization that operates federally funded research and development centers (FFRDCs). In the security community, MITRE operates several foundational programs.

## Names in This Namespace

| Name | Full Name | Identifier Type |
|------|-----------|-----------------|
| `cve` | Common Vulnerabilities and Exposures | `secid:advisory/mitre/cve#*` |
| `cwe` | Common Weakness Enumeration | `secid:weakness/mitre/cwe#*` |
| `attack` | MITRE ATT&CK | `secid:ttp/mitre/attack#*` |
| `atlas` | Adversarial Threat Landscape for AI Systems | `secid:ttp/mitre/atlas#*` |
| `capec` | Common Attack Pattern Enumeration and Classification | `secid:ttp/mitre/capec#*` |

## Examples

```
secid:entity/mitre/cve      # The CVE program
secid:entity/mitre/attack   # The ATT&CK framework
secid:entity/mitre/atlas    # The ATLAS framework
```

## Recent Developments

### CVE Funding Incident (2025)

In April 2025, MITRE's contract to operate CVE nearly expired with short notice. CISA extended funding, but the incident prompted formation of the CVE Foundation as a nonprofit.
