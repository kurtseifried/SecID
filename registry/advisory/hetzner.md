---
type: advisory
namespace: hetzner
full_name: "Hetzner Online"
operator: "secid:entity/hetzner"
website: "https://www.hetzner.com"
status: active

sources:
  status:
    full_name: "Hetzner Status"
    urls:
      website: "https://status.hetzner.com"
      docs: "https://docs.hetzner.com"
    examples:
      - "secid:advisory/hetzner/status"
---

# Hetzner Advisory Sources

Hetzner is a German web hosting and cloud services provider known for cost-effective dedicated servers and cloud instances.

## Advisory Status: Limited

Hetzner does not publish a formal security advisory bulletin. Security information is limited to:

- **Status page** - Service availability and incidents
- **Documentation** - Security best practices

## Available Security Resources

| Resource | URL | Description |
|----------|-----|-------------|
| Status page | status.hetzner.com | Service status and incidents |
| Documentation | docs.hetzner.com | Technical documentation |
| Support | accounts.hetzner.com | Customer support portal |

## Security Practices

Hetzner maintains security through:
- Infrastructure security management
- DDoS protection services
- Firewall offerings
- No public vulnerability disclosure program found

## Why No Formal Advisories?

As a hosting/cloud provider:
- Infrastructure security managed internally
- No public bug bounty program identified
- Security communication through support channels
- Focus on infrastructure rather than software products

## Notes

- No CVE-style advisory identifiers
- Security incidents may appear on status page
- Customer responsible for workload security
- Contact support for security concerns
