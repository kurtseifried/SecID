---
namespace: cisa
full_name: "Cybersecurity and Infrastructure Security Agency"
website: "https://www.cisa.gov"
type: government
founded: 2018
headquarters: "Arlington, Virginia, USA"
parent: "US Department of Homeland Security"
---

# Cybersecurity and Infrastructure Security Agency (CISA)

CISA is the US government agency responsible for protecting critical infrastructure from cyber threats. CISA coordinates vulnerability disclosure, issues security directives, and maintains the KEV (Known Exploited Vulnerabilities) catalog.

## Why CISA Matters

CISA has operational authority over US federal cybersecurity:

- **KEV Catalog** - Authoritative list of vulnerabilities being actively exploited
- **Vulnrichment** - CVE enrichment to address NVD backlog
- **BOD/ED** - Binding Operational Directives and Emergency Directives for federal agencies
- **CVE Program oversight** - Contracts MITRE to operate CVE

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `kev` | Known Exploited Vulnerabilities Catalog | CVE-2021-44228 |
| `vulnrichment` | CVE Enrichment Data | CVE-2024-1234 |

## KEV: Why It's Special

KEV isn't just another vulnerability list - it's a prioritization signal:

- **Confirmed exploitation** - Every KEV entry has evidence of active exploitation
- **Legal mandate** - BOD 22-01 requires federal agencies to remediate KEV entries
- **Quality filter** - ~1,200 entries vs 200,000+ CVEs; only exploited vulnerabilities

Many organizations use KEV status as a prioritization factor even if not legally required.

## Notes

- CISA was created in 2018, replacing NPPD (National Protection and Programs Directorate)
- CISA also handles ICS-CERT advisories for industrial control systems
- CISA's Vulnrichment project helps address NVD's enrichment backlog
