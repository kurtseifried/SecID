# Entity Type (`entity`)

Identifiers for **vendors, products, and services** - stable anchors when PURL/SPDX are unavailable.

## Identifier Format

```
secid:entity/<namespace>/<name>
```

Where:
- `<namespace>` is the vendor/organization (redhat, aws, microsoft, mitre, etc.)
- `<name>` is the product or service within that vendor (openshift, s3, azure, cve, etc.)

## Examples

```
# Vendors and their products/services
secid:entity/redhat/openshift       # OpenShift platform (product & service)
secid:entity/redhat/rhel            # RHEL operating system
secid:entity/aws/s3                 # S3 storage service
secid:entity/aws/lambda             # Lambda compute service
secid:entity/microsoft/azure        # Azure cloud platform
secid:entity/openai/gpt-4           # GPT-4 model

# Organizations that operate security systems
secid:entity/mitre/cve              # CVE program (operated by MITRE)
secid:entity/mitre/attack           # ATT&CK framework
secid:entity/nist/nvd               # National Vulnerability Database
secid:entity/github/ghsa            # GitHub Security Advisories
```

## When to Use Entity Type

Use entity identifiers for:

1. **Vendors and their products/services** that don't have PURL identifiers:
   - Cloud services (AWS S3, Azure Blob, GCP Cloud Storage)
   - Platforms (OpenShift, Kubernetes distributions)
   - AI models (GPT-4, Claude, Gemini)
   - Commercial products without package managers

2. **Organizations that operate security systems** referenced by other SecID types:
   - Advisory database operators (MITRE/CVE, NIST/NVD, GitHub/GHSA)
   - Framework maintainers (MITRE/ATT&CK, OWASP/Top-10)

3. **Things that need stable anchors** in the security knowledge graph

## When NOT to Use Entity Type

- **Packages with PURL support**: Use `pkg:npm/lodash` not `secid:entity/npm/lodash`
- **Vulnerabilities**: Use `secid:advisory/...`
- **Standards/frameworks**: Use `secid:control/...` for controls, `secid:weakness/...` for weakness taxonomies

## Naming Conventions

### Use common names for general concepts

```
entity/redhat/openshift     # The OpenShift platform generally
entity/microsoft/windows    # Windows generally
```

### Use real vendor product names for variants

When you need to distinguish between product variants (e.g., self-managed vs managed service), use the actual names the vendor uses:

```
entity/redhat/openshift           # General OpenShift platform
entity/redhat/rosa                # ROSA (Red Hat OpenShift on AWS)
entity/redhat/openshift-dedicated # OpenShift Dedicated
entity/redhat/aro                 # ARO (Azure Red Hat OpenShift)
```

**Don't invent suffixes** like `-product` or `-service`. If Red Hat calls it "ROSA", use `rosa`.

### Disambiguation for name collisions

Rare, but when needed, use what makes sense:
- Geographic: `company-uk`, `company-us`
- Parent: `subsidiary-parentco`

The general rule: **follow how the vendor/entity identifies it**.

## Namespace Files

Each namespace file (`entity/<namespace>.md`) describes:
- The organization and its security-relevant activities
- Names within the namespace (products, services, systems)
- URLs for resolution
- What identifier types each name issues (if applicable)

## Current Namespaces

| Namespace | Vendor/Organization | Key Products/Services |
|-----------|---------------------|----------------------|
| `mitre` | MITRE Corporation | cve, cwe, attack, atlas, capec |
| `nist` | NIST | nvd |
| `github` | GitHub | ghsa |
| `google` | Google | osv |
| `first` | FIRST | cvss, epss |
| `owasp` | OWASP | top-10, llm-top-10 |
| `csa` | Cloud Security Alliance | ccm, aicm |
| `redhat` | Red Hat | openshift, rhel, ansible |
| `microsoft` | Microsoft | msrc, azure, windows |
| `debian` | Debian Project | debian |
| `cisco` | Cisco | psirt, ios |

