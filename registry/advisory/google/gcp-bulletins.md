---
type: advisory
namespace: google
name: gcp-bulletins
full_name: "Google Cloud Security Bulletins"
operator: "secid:entity/google"

urls:
  website: "https://cloud.google.com/support/bulletins"
  lookup: "https://cloud.google.com/support/bulletins#{id}"

id_pattern: "GCP-\\d{4}-\\d+"
examples:
  - "secid:advisory/google/gcp-bulletins#GCP-2024-001"
  - "secid:advisory/google/gcp-bulletins#GCP-2023-034"

status: active
---

# Google Cloud Security Bulletins

Official security advisories from Google Cloud Platform covering GCP services and infrastructure.

## Format

```
secid:advisory/google/gcp-bulletins#GCP-YYYY-NNN
```

## Resolution

```
https://cloud.google.com/support/bulletins#{id}
```

## Why GCP Bulletins Matter

Google Cloud is a major cloud provider:
- **GKE vulnerabilities** - Kubernetes and container security
- **Compute Engine** - VM and infrastructure issues
- **Service-specific** - Cloud SQL, BigQuery, etc.
- **Shared fate model** - Google's security responsibility clarity

## Related Sources

- **GKE Security Bulletins** - Kubernetes-specific advisories
- **Chrome/Android** - Separate advisory tracks (see google/chrome, google/android)

## Notes

- Bulletins often reference CVEs but include GCP-specific context
- Patch availability and timeline information included
- Some issues are GCP-specific without CVE assignment
