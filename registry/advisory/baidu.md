---
type: advisory
namespace: baidu
full_name: "Baidu"
operator: "secid:entity/baidu"
website: "https://www.baidu.com"
status: limited

sources:
  security:
    full_name: "Baidu Security"
    urls:
      website: "https://sec.baidu.com"
      cloud: "https://cloud.baidu.com"
    examples:
      - "secid:advisory/baidu/security"
---

# Baidu Advisory Sources

Baidu is a major Chinese technology company operating search, cloud (Baidu Cloud), AI services, and autonomous vehicles.

## Advisory Status: Limited

Baidu does not appear to operate a public security advisory system. Vulnerabilities in Baidu products are primarily tracked through:

- **Third-party CVE databases** - CVEDetails, NVD
- **GitHub Advisory Database** - For open-source components
- **Security researchers** - Independent disclosures

## Known Vulnerability Sources

| Source | URL | Description |
|--------|-----|-------------|
| CVEDetails | cvedetails.com/vendor/6986/Baidu.html | CVE tracking |
| GitHub Advisories | github.com/advisories (search Baidu) | Open-source vulns |

## Products with Known CVEs

| Product | Vulnerability Types |
|---------|-------------------|
| Baidu Antivirus | Driver vulnerabilities (BYOVD) |
| UEditor | XSS, unrestricted upload |
| Baidu Browser | Various web browser issues |

## 2024 Notable Vulnerabilities

| CVE | Product | Issue |
|-----|---------|-------|
| CVE-2024-51324 | Baidu Antivirus | BYOVD process termination |
| CVE-2024-7342 | UEditor | Unrestricted file upload |

## Why No Public Advisory System?

- Primary market is China
- No identified public bug bounty program
- Security communication through support channels
- Vulnerabilities discovered by external researchers

## Baidu Cloud

Baidu Cloud (百度智能云) is Baidu's cloud platform:
- No public security advisory bulletin identified
- Security managed internally
- Chinese-language resources primary

## Notes

- Track Baidu vulnerabilities via CVE databases
- No official English security portal found
- Contact Baidu directly for security concerns
- Researcher disclosures often through third parties
