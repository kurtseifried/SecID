---

type: "entity"
namespace: "debian.org"

common_name: "Debian"
full_name: "Debian Project"

urls:
  website: "https://www.debian.org"
  security: "https://www.debian.org/security/"

names:
  debian:
    full_name: "Debian GNU/Linux"
    description: "Community-developed Linux distribution"
    urls:
      website: "https://www.debian.org"
      packages: "https://packages.debian.org"
      tracker: "https://security-tracker.debian.org/tracker"
    issues_type: "advisory"
    issues_namespace: "debian.org"

wikidata: "Q7715973"
status: "active"
established: 1993
---


# Debian

The Debian Project is a volunteer-driven organization that develops and maintains the Debian GNU/Linux distribution. Debian serves as the upstream for many other distributions including Ubuntu.

## Names in This Namespace

| Name | Full Name | Description |
|------|-----------|-------------|
| `debian` | Debian GNU/Linux | Linux distribution |

## Examples

```
secid:entity/debian.org/debian      # Debian Linux distribution
```

## Security Content

Debian operates a comprehensive security response program:

- **DSA**: Debian Security Advisories for stable releases
- **DLA**: Debian LTS Advisories for long-term support
- **Security Tracker**: Tracks CVEs affecting Debian packages

See `advisory/debian` for advisory identifiers.

## Notes

- Debian uses a "stable", "testing", "unstable" release model
- Security support varies by release track
- Many distributions derive from Debian (Ubuntu, Linux Mint, etc.)
