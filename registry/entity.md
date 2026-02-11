# Entity Type (`entity`)

Identifiers for **vendors, products, and services** - stable anchors when PURL/SPDX are unavailable.

## Identifier Format

```
secid:entity/<namespace>[/<name>]
```

Where:
- `<namespace>` is the vendor/organization (redhat, aws, microsoft, mitre, etc.)
- `<name>` (optional) is the product or service within that vendor (openshift, s3, azure, cve, etc.)

## Bare vs. Full Identifiers

SecID supports **bare namespace identifiers** for referencing organizations themselves:

```
secid:entity/redhat           # Red Hat as an organization
secid:entity/redhat.com/rhel      # RHEL operating system (product)
secid:entity/redhat.com/openshift # OpenShift platform (product)
```

### When to Use Bare Identifiers

Use `secid:entity/<namespace>` (no name) when:
- Referring to the **organization itself**, not a specific product
- The organization **is** the relevant entity (e.g., as an `operator` reference)
- Discussing vendor-level concerns (security practices, trust, policies)

Examples:
```
secid:entity/mitre      # MITRE Corporation (the organization)
secid:entity/nist       # NIST (the organization)
secid:entity/owasp      # OWASP Foundation (the organization)
```

### When to Use Full Identifiers

Use `secid:entity/<namespace>/<name>` when:
- Referring to a **specific product, service, or system**
- The product has its own security surface distinct from the vendor
- You need precision about what's affected

Examples:
```
secid:entity/mitre.org/cve      # CVE program (operated by MITRE)
secid:entity/nist.gov/nvd       # NVD (operated by NIST)
secid:entity/redhat.com/rhel    # RHEL (product from Red Hat)
```

### Operator References

The `operator` field in registry files typically uses bare identifiers:

```yaml
# In registry/advisory/org/mitre.md
operator: "secid:entity/mitre.org"    # MITRE operates the CVE program

# In registry/advisory/gov/nist.md
operator: "secid:entity/nist.gov"     # NIST operates the NVD
```

This indicates which organization is responsible for the advisory source, not which specific product.

## Examples

```
# Vendors and their products/services
secid:entity/redhat.com/openshift       # OpenShift platform (product & service)
secid:entity/redhat.com/rhel            # RHEL operating system
secid:entity/aws.amazon.com/s3                 # S3 storage service
secid:entity/aws.amazon.com/lambda             # Lambda compute service
secid:entity/microsoft.com/azure        # Azure cloud platform

# AI vendors and models
secid:entity/openai.com/gpt-4           # GPT-4 model
secid:entity/openai.com/gpt-4o          # GPT-4o model
secid:entity/anthropic.com/claude       # Claude model family
secid:entity/anthropic.com/claude-3-5   # Claude 3.5 Sonnet
secid:entity/google.com/gemini          # Gemini model family
secid:entity/meta.com/llama             # Llama model family
secid:entity/mistral/mistral        # Mistral models

# AI infrastructure and tools
secid:entity/langchain/langchain    # LangChain framework
secid:entity/huggingface/hub        # HuggingFace model hub
secid:entity/huggingface/transformers # Transformers library

# Organizations that operate security systems
secid:entity/mitre.org/cve              # CVE program (operated by MITRE)
secid:entity/mitre.org/attack           # ATT&CK framework
secid:entity/nist.gov/nvd               # National Vulnerability Database
secid:entity/github.com/ghsa            # GitHub Security Advisories
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
entity/redhat.com/openshift     # The OpenShift platform generally
entity/microsoft.com/windows    # Windows generally
```

### Use real vendor product names for variants

When you need to distinguish between product variants (e.g., self-managed vs managed service), use the actual names the vendor uses:

```
entity/redhat.com/openshift           # General OpenShift platform
entity/redhat.com/rosa                # ROSA (Red Hat OpenShift on AWS)
entity/redhat.com/openshift-dedicated # OpenShift Dedicated
entity/redhat.com/aro                 # ARO (Azure Red Hat OpenShift)
```

**Don't invent suffixes** like `-product` or `-service`. If Red Hat calls it "ROSA", use `rosa`.

### Disambiguation for name collisions

Rare, but when needed, use what makes sense:
- Geographic: `company-uk`, `company-us`
- Parent: `subsidiary-parentco`

The general rule: **follow how the vendor/entity identifies it**.

## Namespace Files

Each namespace file (`entity/<tld>/<domain>.md`) describes:
- The organization and its security-relevant activities
- Names within the namespace (products, services, systems)
- URLs for resolution
- What identifier types each name issues (if applicable)

## Current Namespaces

### Security Organizations

| Namespace | Vendor/Organization | Key Products/Services |
|-----------|---------------------|----------------------|
| `mitre.org` | MITRE Corporation | cve, cwe, attack, atlas, capec |
| `nist.gov` | NIST | nvd, csf, 800-53 |
| `cisa.gov` | CISA | kev, vulnrichment |
| `first.org` | FIRST | cvss, epss |
| `owasp.org` | OWASP | top-10, llm-top-10, asvs |
| `cloudsecurityalliance.org` | Cloud Security Alliance | ccm, aicm |

### AI Vendors

| Namespace | Vendor/Organization | Key Products/Services |
|-----------|---------------------|----------------------|
| `openai.com` | OpenAI | gpt-4, gpt-4o, chatgpt |
| `anthropic.com` | Anthropic | claude, claude-3-5 |
| `google.com` | Google | gemini, bard, osv |
| `meta.com` | Meta | llama |
| `mistral.ai` | Mistral AI | mistral, mixtral |
| `huggingface.co` | HuggingFace | hub, transformers |

### Infrastructure Vendors

| Namespace | Vendor/Organization | Key Products/Services |
|-----------|---------------------|----------------------|
| `aws.amazon.com` | Amazon Web Services | s3, lambda, ec2, alas |
| `microsoft.com` | Microsoft | azure, msrc, windows |
| `redhat.com` | Red Hat | openshift, rhel, ansible |
| `github.com` | GitHub | ghsa, actions |
| `cisco.com` | Cisco | psirt, ios |
| `debian.org` | Debian Project | debian |

