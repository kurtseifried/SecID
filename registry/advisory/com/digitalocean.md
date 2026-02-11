---
type: advisory
namespace: digitalocean.com
full_name: "DigitalOcean"
operator: "secid:entity/digitalocean.com"
website: "https://www.digitalocean.com"
status: active

sources:
  security:
    full_name: "DigitalOcean Security"
    urls:
      website: "https://www.digitalocean.com/security"
      bug-bounty: "https://app.intigriti.com/programs/digitalocean/digitalocean"
      blog: "https://www.digitalocean.com/blog/tag/security"
    examples:
      - "secid:advisory/digitalocean.com/security"
---

# DigitalOcean Advisory Sources

DigitalOcean is a cloud infrastructure provider focused on developers and small-to-medium businesses.

## Advisory Status: Limited

DigitalOcean does not publish a formal security advisory bulletin. Security information is available through:

- **Bug bounty program** - Intigriti (formerly HackerOne)
- **Security blog posts** - Incident responses (Log4j, Mailchimp, etc.)
- **Status page** - Service availability

## Available Security Resources

| Resource | URL | Description |
|----------|-----|-------------|
| Security page | digitalocean.com/security | Overview of security practices |
| Bug bounty | app.intigriti.com/programs/digitalocean | Vulnerability disclosure |
| Blog | digitalocean.com/blog/tag/security | Security-related posts |
| Status | status.digitalocean.com | Service status |

## Bug Bounty Program

DigitalOcean runs a paid public bug bounty program:
- Launched publicly April 2024
- Hosted on Intigriti
- Scope includes core infrastructure
- Excludes marketplace apps from partners

## Notable Security Responses

| Date | Incident |
|------|----------|
| 2021 | Log4Shell response |
| 2022 | Mailchimp security incident impact |

## Why No Formal Advisories?

As a cloud provider, DigitalOcean:
- Manages infrastructure security internally
- Patches services without customer action needed
- Communicates via blog for major incidents
- Uses status page for service disruptions

## Notes

- No CVE-style advisory identifiers
- Security issues communicated via blog posts
- Customer workload security is customer responsibility
