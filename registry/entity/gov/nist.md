---

type: "entity"
namespace: "nist.gov"

common_name: "NIST"
full_name: "National Institute of Standards and Technology"

urls:
  website: "https://www.nist.gov"

names:
  nvd:
    full_name: "National Vulnerability Database"
    urls:
      website: "https://nvd.nist.gov"
      api: "https://services.nvd.nist.gov/rest/json/cves/2.0"
      bulk_data: "https://nvd.nist.gov/vuln/data-feeds"
    issues_type: "advisory"
    issues_namespace: "nvd"

wikidata: "Q176691"
status: "active"
established: 1901
---


# NIST

NIST is a US federal agency within the Department of Commerce. In the security context, NIST is known for:

- **NVD** - National Vulnerability Database (CVE enrichment)
- **NIST Cybersecurity Framework** - Risk management framework
- **SP 800 series** - Security guidelines and standards

## Names in This Namespace

| Name | Full Name | Identifier Type |
|------|-----------|-----------------|
| `nvd` | National Vulnerability Database | `secid:advisory/nist.gov/nvd#*` |
| `csf` | Cybersecurity Framework | `secid:control/nist.gov/csf#*` |
| `800-53` | SP 800-53 Security Controls | `secid:control/nist.gov/800-53#*` |

## Examples

```
secid:entity/nist.gov/nvd       # The NVD system
```
