# SecID Specification

Version: 0.9
Status: Public Draft - Open for Comment

> **This is a draft specification.** We welcome feedback, questions, and suggestions. Please open an issue at [github.com/kurtseifried/SecID/issues](https://github.com/kurtseifried/SecID/issues) or submit a pull request.

## 1. Overview

**SecID provides a grammar and registry for referencing security knowledge. SecID does not assign identifiers—those come from their respective authorities.**

SecID is directly modeled after [Package URL (PURL)](https://github.com/package-url/purl-spec). It provides a consistent way to reference existing databases like CVE, CWE, ATT&CK, and ISO standards.

**SecID does not replace CVE, CWE, ATT&CK, or any other authority.** It references them. `secid:advisory/mitre/cve#CVE-2024-1234` points to MITRE's CVE record; it doesn't create a new one. CVE-2024-1234 is assigned by MITRE—SecID provides a consistent way to reference it.

**SecID identifies things. It does not imply authority, truth, severity, or correctness.**

This is intentionally aligned with PURL:
- Identity ≠ metadata
- Identity ≠ trust
- Identity ≠ location

Resolution, dereferencing, or retrieval happens via APIs outside the identifier itself.

### 1.1 Relationship to PURL

Package URL (PURL) provides a universal scheme for identifying software packages: `pkg:<type>/<namespace>/<name>`. But PURL is explicitly for packages only.

In the security world, we need to identify many things that aren't packages: advisories, weaknesses, attack techniques, controls, regulations, entities, and reference documents. Rather than invent something new, we essentially created a "package URL" for each category of security knowledge we needed to identify.

**Why `secid:`?** PURL uses `pkg:` as its scheme for packages. SecID uses `secid:` as its scheme for security knowledge. What follows the scheme is identical to PURL grammar: `type/namespace/name[@version][?qualifiers][#subpath]`. Everywhere in SecID, we're using PURL-compliant grammar - just with `secid:` as the scheme because we're identifying security knowledge, not software packages.

### 1.2 Exact PURL to SecID Mapping

SecID is PURL with a different scheme. The grammar is identical:

```
PURL:   pkg:type/namespace/name@version?qualifiers#subpath
SecID:  secid:type/namespace/name@version?qualifiers#subpath
```

**Component-by-component mapping:**

| PURL Component | SecID Component | Required | SecID Usage |
|----------------|-----------------|----------|-------------|
| `pkg:` | `secid:` | Yes | Scheme (constant prefix) |
| `type` | `type` | Yes | Security domain: `advisory`, `weakness`, `ttp`, `control`, `regulation`, `entity`, `reference` |
| `namespace` | `namespace` | Yes | **Organization** that publishes/maintains (e.g., `mitre`, `nist`, `csa`, `redhat`, `iso`, `owasp`) |
| `name` | `name` | Yes | **Database/framework/standard** they publish (e.g., `cve`, `nvd`, `cwe`, `attack`, `ccm`, `27001`) |
| `@version` | `@version` | No | Edition or revision (e.g., `@4.0`, `@2022`, `@2.0`) |
| `?qualifiers` | `?qualifiers` | No | Optional context that doesn't change identity (e.g., `?lang=ja`) |
| `#subpath` | `#subpath` | No | **Specific item** within the database/framework (e.g., `#CVE-2024-1234`, `#CWE-79`, `#T1059`, `#A.8.1`) |

**Visual breakdown:**

```
secid:advisory/mitre/cve#CVE-2024-1234
────┬─ ───┬─── ──┬── ─┬─ ──────┬──────
    │     │      │    │        └─ #subpath: specific item (CVE-2024-1234)
    │     │      │    └────────── name: database they publish (cve)
    │     │      └─────────────── namespace: organization (mitre)
    │     └────────────────────── type: security domain (advisory)
    └──────────────────────────── scheme: always "secid:"

secid:control/iso/27001@2022#A.8.1
────┬─ ──┬─── ─┬─ ──┬── ─┬── ──┬──
    │    │     │    │    │     └─ #subpath: specific control (A.8.1)
    │    │     │    │    └─────── @version: edition (2022)
    │    │     │    └──────────── name: standard (27001)
    │    │     └───────────────── namespace: organization (iso)
    │    └─────────────────────── type: security domain (control)
    └──────────────────────────── scheme: always "secid:"

secid:weakness/owasp/top10@2021#A03
────┬─ ───┬──── ──┬── ──┬── ─┬── ─┬─
    │     │       │     │    │    └─ #subpath: specific weakness (A03)
    │     │       │     │    └────── @version: edition year (2021)
    │     │       │     └─────────── name: framework (top10)
    │     │       └────────────────── namespace: organization (owasp)
    │     └────────────────────────── type: security domain (weakness)
    └──────────────────────────────── scheme: always "secid:"
```

**Key insight:** The namespace is always the **organization** (who publishes it), the name is the **thing they publish** (database, framework, standard), and the subpath is the **specific item within** that thing.

**Subpath hierarchy:** Subpaths can use `/` to express hierarchy within a document (just like PURL):

```
secid:control/csa/ccm@4.0#IAM-12                        # The control
secid:control/csa/ccm@4.0#IAM-12/audit                  # Audit section within control
secid:control/csa/ccm@4.0#IAM-12/implementation         # Implementation guidance
secid:regulation/eu/gdpr#art-32/1/a                     # Article 32(1)(a)
secid:weakness/mitre/cwe#CWE-79/potential-mitigations   # Mitigations section within CWE
secid:ttp/mitre/attack#T1059/detection                  # Detection guidance for technique
```

**Percent encoding:** Special characters in names and subpaths must be percent-encoded (URL encoding). This ensures cross-platform compatibility and safe storage/transport:

| Character | Encoded | Example |
|-----------|---------|---------|
| Space | `%20` | `Auditing Guidelines` → `Auditing%20Guidelines` |
| `&` | `%26` | `A&A-01` → `A%26A-01` |
| `(` `)` | `%28` `%29` | `(Draft)` → `%28Draft%29` |
| `/` | `%2F` | Only encode if literal (not a hierarchy separator) |
| `#` | `%23` | Only encode if literal (not the subpath prefix) |
| `@` | `%40` | Only encode if literal (not the version prefix) |
| `?` | `%3F` | Only encode if literal (not the qualifier prefix) |

```
secid:control/csa/aicm@1.0#A%26A-01                     # A&A-01 control (& encoded)
secid:control/csa/ccm@4.0#IAM-12/Auditing%20Guidelines  # Section with space
secid:control/nist/800-53#AC-1/Control%20Enhancements  # Section with space
```

Tools should render identifiers human-friendly for display while storing the encoded form. See Section 8.2 for complete encoding rules.

**Registry file mapping:** Every level of the SecID hierarchy maps to a registry file:

```
SecID:                          Registry File:
secid:advisory                  → registry/advisory.md (type definition)
secid:advisory/redhat           → registry/advisory/redhat.md (namespace, all sources)
secid:advisory/redhat/cve       → section within registry/advisory/redhat.md
secid:weakness                  → registry/weakness.md (type definition)
secid:weakness/mitre            → registry/weakness/mitre.md (namespace, all sources)
secid:control/nist              → registry/control/nist.md (namespace, all sources)
```

**One file per namespace.** Each namespace file contains ALL sources for that namespace. For example, `registry/advisory/redhat.md` contains rules for `cve`, `errata`, and `bugzilla`—not separate files for each.

Each registry file contains:
- Metadata (namespace, full name, website, status)
- Sections for each source with ID patterns and URL templates
- Examples and documentation

For example, `registry/weakness/mitre.md` contains the rules for resolving CWE:

```yaml
# In registry/weakness/mitre.md
---
namespace: mitre
full_name: "MITRE Corporation"
website: "https://mitre.org"
status: active
---

# MITRE (Weakness Namespace)

## Sources

### cwe

| Field | Value |
|-------|-------|
| id_pattern | `CWE-\d+` |
| url_template | `https://cwe.mitre.org/data/definitions/{num}.html` |
| example | `secid:weakness/mitre/cwe#CWE-79` |
```

Resolution process:
```
secid:weakness/mitre/cwe#CWE-123
  → Find registry/weakness/mitre.md
  → Find "cwe" section, get id_pattern and url_template
  → Extract "123" from "CWE-123" using id_pattern
  → Apply to url_template: https://cwe.mitre.org/data/definitions/123.html
```

**More examples showing the pattern:**

| SecID | namespace (org) | name (what they publish) | subpath (specific item) |
|-------|-----------------|--------------------------|-------------------------|
| `secid:advisory/mitre/cve#CVE-2024-1234` | MITRE | CVE database | CVE-2024-1234 |
| `secid:advisory/nist/nvd#CVE-2024-1234` | NIST | NVD database | CVE-2024-1234 |
| `secid:advisory/redhat/errata#RHSA-2024:1234` | Red Hat | Errata system | RHSA-2024:1234 |
| `secid:weakness/mitre/cwe#CWE-79` | MITRE | CWE taxonomy | CWE-79 |
| `secid:ttp/mitre/attack#T1059` | MITRE | ATT&CK framework | T1059 |
| `secid:ttp/mitre/capec#CAPEC-66` | MITRE | CAPEC catalog | CAPEC-66 |
| `secid:control/csa/ccm@4.0#IAM-12` | CSA | CCM framework | IAM-12 |
| `secid:control/nist/csf@2.0#PR.AC-1` | NIST | CSF framework | PR.AC-1 |
| `secid:control/iso/27001@2022#A.8.1` | ISO | 27001 standard | A.8.1 |
| `secid:regulation/eu/gdpr#art-32` | EU | GDPR regulation | Article 32 |

### 1.3 Comparison with PURL Examples

| What you're identifying | Scheme | Example |
|------------------------|--------|---------|
| Software packages | `pkg:` | `pkg:npm/lodash@4.17.21` |
| Vulnerability advisories | `secid:` | `secid:advisory/mitre/cve#CVE-2024-1234` |
| Weakness patterns | `secid:` | `secid:weakness/mitre/cwe#CWE-79` |
| Attack techniques | `secid:` | `secid:ttp/mitre/attack#T1059` |
| Security controls | `secid:` | `secid:control/nist/csf@2.0#PR.AC-1` |
| Regulations | `secid:` | `secid:regulation/eu/gdpr#art-32` |
| Entities | `secid:` | `secid:entity/mitre/cve` |
| Reference documents | `secid:` | `secid:reference/whitehouse/eo-14110` |

Think of it this way: `secid:` is the scheme (like `pkg:`), and what follows uses the exact same grammar as PURL.

### 1.4 Divergences from PURL

SecID uses PURL grammar but diverges in three specific ways:

#### 1. Scheme: `secid:` instead of `pkg:`

PURL uses `pkg:` to identify packages. SecID uses `secid:` to identify security knowledge. This is the expected way to use PURL grammar for a different domain.

#### 2. Type: Security domains instead of package ecosystems

PURL types are package ecosystems: `npm`, `pypi`, `maven`, `cargo`, `nuget`, etc.

SecID types are security domains: `advisory`, `weakness`, `ttp`, `control`, `regulation`, `entity`, `reference`.

This is semantic, not structural - the grammar is identical, just the vocabulary differs.

#### 3. Subpath: Identifier references instead of file paths

**This is the significant divergence.**

In PURL, `#subpath` is defined as "a subpath within the package, relative to the package root" - meant for file paths like `pkg:npm/lodash@4.17.21#lib/fp.js`.

In SecID, `#subpath` identifies **specific items within a database or framework**:

```
secid:advisory/mitre/cve#CVE-2024-1234       # A specific CVE
secid:weakness/mitre/cwe#CWE-79              # A specific weakness
secid:ttp/mitre/attack#T1059.003             # A specific technique
secid:control/nist/800-53@r5#AC-1            # A specific control
secid:control/iso/27001@2022#A.8.1           # An ISO Annex control
secid:advisory/redhat/errata#RHSA-2024:1234  # A Red Hat advisory
```

**Why this divergence is necessary:**

Security databases aren't packages with files - they're registries of identifiers. CVE-2024-1234 isn't a file path; it's an identifier within the CVE database. The subpath lets us say "this specific item within that database" using PURL-compatible syntax.

**Extended subpath semantics:**

Because security knowledge is often hierarchical, SecID subpaths support:

1. **Identifier prefixes** - Different item types within one name:
   ```
   secid:advisory/redhat/errata#RHSA-2024:1234  # Security Advisory
   secid:advisory/redhat/errata#RHBA-2024:5678  # Bug Advisory
   secid:advisory/redhat/errata#RHEA-2024:9012  # Enhancement Advisory
   ```

2. **Hierarchical references** using `/`:
   ```
   secid:control/csa/ccm@4.0#IAM-12/audit           # Audit section of control
   secid:regulation/eu/gdpr#art-32/1/a              # Article 32(1)(a)
   secid:weakness/mitre/cwe#CWE-79/mitigations      # Mitigations for CWE-79
   ```

3. **Framework-specific patterns**:
   ```
   secid:ttp/mitre/attack#T1059.003    # Sub-technique (ATT&CK uses dots)
   secid:control/iso/27001@2022#A.8.1  # Annex control (ISO uses dots)
   secid:control/nist/800-53@r5#AC-1   # Control family-number format
   ```

Each registry file documents its subpath patterns and how to resolve them to URLs.

### 1.3 Scope: What SecID Identifies (and What It Doesn't)

**SecID identifies structured security knowledge with defined namespaces.** This includes:
- Advisories from known sources (CVE, GHSA, vendor advisories)
- Weakness taxonomies (CWE, OWASP Top 10)
- Attack techniques (ATT&CK, ATLAS, CAPEC)
- Security controls (NIST CSF, ISO 27001, CIS Controls)
- Regulations (GDPR, HIPAA)
- Entities (organizations, products, services)
- Reference documents (standards, research papers, executive orders)

**SecID does not assign identifiers.** SecID maintains a registry of identifier *systems* (CVE, GHSA, CWE, etc.) and provides a grammar to reference identifiers within those systems. The identifiers themselves (CVE-2024-1234, CWE-79, T1059) are assigned by their respective authorities (MITRE, GitHub, NIST, etc.).

**SecID does NOT provide identifiers for arbitrary URLs.** There is no `secid:url/...` type.

| What | In Scope? | Reason |
|------|-----------|--------|
| `secid:advisory/mitre/cve#CVE-2024-1234` | ✅ Yes | Structured security knowledge with namespace |
| `secid:weakness/mitre/cwe#CWE-79` | ✅ Yes | Structured security knowledge with namespace |
| `secid:url/https://example.com/...` | ❌ No | URLs are already identifiers; no need to wrap them |
| `https://stackoverflow.com/a/12345678` | ❌ No | Not a SecID - just a URL |

**Why exclude arbitrary URLs?**

1. **URLs are already identifiers** - Wrapping a URL in `secid:url/...` adds no value; the URL itself is globally unique
2. **Encoding nightmare** - URLs contain `:`, `/`, `?`, `#` which are reserved in SecID, requiring ugly percent-encoding
3. **Breaks the namespace model** - SecID's value comes from `type/namespace/name` structure; arbitrary URLs have no namespace
4. **Redundant resolution** - `secid:url/X` would just resolve to `X`

**What about referencing arbitrary web content?**

SecID APIs and relationship/enrichment databases MAY support arbitrary URLs as query inputs and relationship targets. This is an API/database feature, not part of the identifier specification.

For example, a SecID API might accept:
```
GET /api/v1/lookup?secid=secid:weakness/mitre/cwe%23CWE-732
GET /api/v1/lookup?url=https://stackoverflow.com/a/12345678
```

Both are valid queries to the API. The URL query returns any relationship/enrichment data associated with that URL in the database. But the URL itself is not a SecID - it's a URL that the API happens to support.

This separation keeps the identifier specification focused while allowing implementations flexibility.

## 2. Grammar

SecID follows PURL's grammar exactly, with `secid:` as the scheme:

```
secid:type/namespace/name@version?qualifiers#subpath
```

### 2.1 Components

| Component | Required | Description |
|-----------|----------|-------------|
| `secid:` | Yes | The URL scheme (constant, like `pkg:` in PURL) |
| `type` | Yes | The security domain: advisory, weakness, ttp, control, regulation, entity, reference |
| `namespace` | Yes | The organization that publishes/maintains (mitre, nist, csa, owasp, etc.) |
| `name` | Yes | The database/framework/document they publish (cve, nvd, ccm, attack, etc.) |
| `@version` | No | Edition or revision of the thing itself |
| `?qualifiers` | No | Optional disambiguation or scope |
| `#subpath` | No | The specific item within the document (CVE-2024-1234, IAM-12, T1059, etc.) |

### 2.2 Hard Rules

1. The primary identifier must live in `name`, never in qualifiers
2. Qualifiers never define identity, only context
3. Subpaths reference internal structure (articles, sections, controls) - can use `/` for hierarchy
4. Canonical form always includes `secid:`, type, and namespace
5. Shorthands may exist for display but must normalize to canonical

### 2.3 Examples

```
secid:advisory/mitre/cve#CVE-2024-1234
secid:advisory/nist/nvd#CVE-2024-1234
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz
secid:advisory/redhat/errata#RHSA-2024:1234
secid:weakness/mitre/cwe#CWE-79
secid:ttp/mitre/attack#T1059.003
secid:control/csa/ccm@4.0#IAM-12
secid:control/csa/aicm@1.0#IAM-12/Auditing%20Guidelines
secid:regulation/eu/gdpr@2016-04-27
secid:regulation/eu/gdpr#art-32
secid:entity/mitre/cve
secid:entity/openai/gpt-4
secid:reference/whitehouse/eo-14110
secid:reference/arxiv/2303.08774
```

## 3. Types

SecID defines seven types. No type overlaps another - each answers a different question.

| Type | What it identifies | Question it answers |
|------|-------------------|---------------------|
| `advisory` | Publications/records about vulnerabilities | "What's known about this vulnerability?" |
| `weakness` | Abstract flaw patterns | "What kind of mistake is this?" |
| `ttp` | Adversary techniques and behaviors | "How do attackers do this?" |
| `control` | Security requirements and capabilities that implement them | "How do we prevent/detect this?" |
| `regulation` | Laws and binding legal requirements | "What does the law require?" |
| `entity` | Vendors, products, services, platforms | "What/who is this?" |
| `reference` | Documents, publications, research | "What source supports this?" |

### 3.1 Advisory

Publications, records, or analyses about vulnerabilities.

```
secid:advisory/mitre/cve#CVE-2024-1234        # CVE record (canonical)
secid:advisory/nist/nvd#CVE-2024-1234         # NVD enrichment
secid:advisory/github/ghsa#GHSA-xxxx-yyyy     # GitHub Security Advisory
secid:advisory/google/osv#PYSEC-2024-1        # OSV/PyPI advisory
secid:advisory/redhat/cve#CVE-2024-1234       # Red Hat CVE page
secid:advisory/redhat/errata#RHSA-2024:1234   # Red Hat Security Advisory
secid:advisory/debian/dsa#DSA-5678-1          # Debian Security Advisory
secid:advisory/ubuntu/usn#USN-6789-1          # Ubuntu Security Notice
```

**Why "advisory" instead of "vulnerability"?**

A vulnerability doesn't exist without a description. The CVE Record IS what defines the CVE - there's no platonic vulnerability floating in the ether independent of some advisory describing it. CVE and OSV are "canonical" not because they live in a special namespace, but because other advisories reference them.

**Vendor advisory ID routing:**

For vendors with multiple systems, the ID pattern determines routing:

```yaml
# Entity definition for advisory/redhat namespace
namespace: redhat
id_routing:
  - pattern: "CVE-*"
    system: "Red Hat CVE Database"
  - pattern: "RHSA-*"
    system: "Red Hat Security Advisory"
  - pattern: "RHBA-*"
    system: "Red Hat Bug Advisory"
  - pattern: "RHEA-*"
    system: "Red Hat Enhancement Advisory"
```

### 3.2 Weakness

Abstract, recurring flaw patterns - the "what kind of mistake" that underlies vulnerabilities.

```
secid:weakness/mitre/cwe#CWE-79               # Cross-site Scripting
secid:weakness/mitre/cwe#CWE-89               # SQL Injection
secid:weakness/mitre/cwe#CWE-1427             # Prompt Injection
secid:weakness/owasp/top10@2021#A03           # Injection (2021)
secid:weakness/owasp/llm-top10@2.0#LLM01      # Prompt Injection
```

Multiple advisories can share the same weakness type.

### 3.3 TTP (Tactics, Techniques, Procedures)

Reusable adversary behaviors - how attacks are carried out.

```
secid:ttp/mitre/attack#T1059               # Command and Scripting Interpreter
secid:ttp/mitre/attack#T1059.003           # Windows Command Shell
secid:ttp/mitre/attack#TA0001              # Initial Access (tactic)
secid:ttp/mitre/atlas#AML.T0043            # Prompt Injection
secid:ttp/mitre/atlas#AML.T0051            # LLM Jailbreak
secid:ttp/mitre/capec#CAPEC-66             # SQL Injection attack pattern
```

### 3.4 Control

Security requirements (from frameworks) or capabilities (from vendors).

```
secid:control/csa/ccm@4.0#IAM-12              # CSA CCM control
secid:control/csa/ccm@4.0#IAM-12/audit        # Audit guidance within control
secid:control/csa/aicm@1.0#INP-01             # CSA AI Controls Matrix control
secid:control/nist/csf@2.0#PR.AC-1            # NIST CSF subcategory
secid:control/cis/controls@8.0#1.1            # CIS Control
secid:control/iso/27001@2022#A.8.1            # ISO 27001 Annex A control
```

### 3.5 Regulation

Laws, directives, and binding legal requirements.

```
secid:regulation/eu/gdpr                   # GDPR
secid:regulation/eu/gdpr@2016-04-27        # GDPR with version date
secid:regulation/eu/gdpr#art-32            # Article 32
secid:regulation/eu/gdpr#art-32/1/a        # Article 32(1)(a)
secid:regulation/us/hipaa                  # HIPAA
secid:regulation/us/hipaa#164.312/a/1      # Security Rule citation
secid:regulation/us/sox                    # Sarbanes-Oxley
secid:regulation/eu/nis2                   # NIS2 Directive
```

### 3.6 Entity

Organizations, products, services, platforms - stable anchors when PURL/SPDX are unavailable.

```
secid:entity/mitre/cve                     # CVE program (operated by MITRE)
secid:entity/mitre/cwe                     # CWE taxonomy
secid:entity/mitre/attack                  # ATT&CK framework
secid:entity/nist/nvd                      # NVD (operated by NIST)
secid:entity/openai/gpt-4                  # GPT-4 product
secid:entity/aws/s3                        # S3 service
secid:entity/redhat/rhel                   # RHEL product
```

The namespace is the organization; the name is the specific thing (product, service, system) within that organization. The namespace definition file (e.g., `registry/entity/mitre.md`) describes the organization itself.

### 3.7 Reference

Documents, publications, and research that don't fit into other categories. The reference type has a **deliberately narrow scope** to avoid duplicating what other types cover well.

```
secid:reference/whitehouse/eo-14110           # Executive Order on AI
secid:reference/whitehouse/eo-14028           # Cybersecurity Executive Order
secid:reference/whitehouse/m-24-10            # OMB AI Governance Memo
secid:reference/arxiv/2303.08774              # GPT-4 Technical Report
secid:reference/arxiv/2307.03109              # Jailbroken paper
secid:reference/arxiv/2402.05369              # Sleeper Agents paper
```

**What belongs in reference:**
- White House executive orders and policy documents
- Research papers (particularly AI security research on arXiv)
- Primary sources that inform security practices

**What does NOT belong in reference:**
- NIST publications → Use `control/nist/*` for frameworks, entity for systems
- ISO standards → Use `control/iso/*`
- OWASP documents → Use `weakness/owasp/*`
- Vendor security pages → Use `advisory/*` or `entity/*`

**Reference namespaces (current):**
```
whitehouse      # White House publications (EOs, NSMs, OMB memos)
arxiv           # ArXiv preprints (AI/ML security research)
```

Additional namespaces may be added when there's a clear need for documents that genuinely don't fit elsewhere.

**Subpaths:**

```
secid:reference/whitehouse/eo-14110#section-4.1   # Specific section
secid:reference/arxiv/2303.08774#appendix-a       # Paper appendix
```

**Note:** Document classification (research paper, position paper, etc.) lives in metadata, not in the identifier.

## 4. Namespaces

Namespaces identify the system that issued the identifier.

### 4.0 Namespaces and the Registry

Each type has a directory in the registry. **One file per namespace** contains all sources for that namespace:

```
registry/
├── advisory.md              # Type definition (what is an advisory?)
├── advisory/                # Advisory namespaces
│   ├── mitre.md             # MITRE: cve source
│   ├── nist.md              # NIST: nvd source
│   ├── github.md            # GitHub: ghsa source
│   └── redhat.md            # Red Hat: cve, errata, bugzilla sources (ALL IN ONE FILE)
├── weakness.md              # Type definition (what is a weakness?)
├── weakness/
│   ├── mitre.md             # MITRE: cwe source
│   └── owasp.md             # OWASP: top10, llm-top10, etc. (ALL IN ONE FILE)
├── entity.md                # Type definition (what is an entity?)
├── entity/
│   ├── mitre.md             # MITRE organization
│   └── redhat.md            # Red Hat organization
...
```

The namespace file (e.g., `registry/advisory/redhat.md`) contains sections for each source with rules for parsing and resolving `#subpath` (e.g., `#CVE-2024-1234` or `#RHSA-2025:1234`).

### 4.1 Naming Conventions

**Namespace = organization, Name = what they publish:**
```
secid:advisory/mitre/cve#CVE-2024-1234   # namespace=mitre, name=cve
secid:advisory/nist/nvd#CVE-2024-1234    # namespace=nist, name=nvd
secid:advisory/github/ghsa#GHSA-xxxx     # namespace=github, name=ghsa
secid:weakness/mitre/cwe#CWE-79          # namespace=mitre, name=cwe
secid:ttp/mitre/attack#T1059             # namespace=mitre, name=attack
```

**Keep names short and recognizable:**
```
cve         # Not "common-vulnerabilities-and-exposures"
cwe         # Not "common-weakness-enumeration"
attack      # Not "att-and-ck" or "adversarial-tactics"
nvd         # Not "national-vulnerability-database"
```

**Framework examples:**
```
secid:control/csa/ccm@4.0#IAM-12         # CSA Cloud Controls Matrix
secid:control/csa/aicm@1.0#INP-01        # CSA AI Controls Matrix
secid:control/nist/csf@2.0#PR.AC-1       # NIST Cybersecurity Framework
secid:weakness/owasp/top10@2021#A03      # OWASP Top 10
secid:weakness/owasp/llm-top10@2.0#LLM01 # OWASP LLM Top 10
```

**For vendors with multiple databases, use different names:**
```
secid:advisory/redhat/cve#CVE-2024-1234      # Red Hat CVE database
secid:advisory/redhat/errata#RHSA-2024:1234  # Red Hat errata system
secid:advisory/debian/dsa#DSA-5678-1         # Debian Security Advisory
secid:advisory/debian/dla#DLA-1234-1         # Debian LTS Advisory
```

### 4.2 Namespace Governance

- Namespaces are assigned, not discovered
- Common systems get short names
- Unknown or third-party systems may require longer names
- Namespaces identify identifier systems, not trust

### 4.3 Namespace Documentation

Each namespace has a documentation file explaining:
- What identifiers it issues
- URLs for lookup/resolution
- How to reference items within documents (subpath conventions)
- Version history and conventions

See Section 8 for the entity registry format used for namespace documentation.

## 5. Versions, Qualifiers, and Subpaths

### 5.1 Version (`@version`)

Pins a specific edition of the thing itself. Use version when the **content changes across releases**.

#### When to Use Versions

| Scenario | Use Version? | Example |
|----------|--------------|---------|
| Framework releases | Yes | `@4.0`, `@8.0`, `@2.0` |
| Law publication dates | Yes | `@2016-04-27`, `@2022` |
| Annual updates | Yes | `@2021`, `@2024` |
| Scoring system versions | Yes | `@3.1`, `@4.0` |
| Static IDs that never change | No | CVE IDs don't need versions |

#### Version Format Conventions

**Semantic versions** - for frameworks with numbered releases:
```
secid:control/csa/ccm@4.0#IAM-12           # CCM version 4.0
secid:control/cis/controls@8.0#1.1         # CIS Controls v8
secid:control/nist/csf@2.0#PR.AC-1         # NIST CSF 2.0
secid:weakness/owasp/top10@2021#A03        # OWASP Top 10 2021 edition
secid:weakness/owasp/llm-top10@2.0#LLM01   # OWASP LLM Top 10 v2
```

**Date versions** - for laws and dated publications:
```
secid:regulation/eu/gdpr@2016-04-27        # GDPR publication date
secid:regulation/eu/ai-act@2024-08-01      # EU AI Act effective date
secid:regulation/us/hipaa@1996             # Year for older laws
```

**Year versions** - for annual updates:
```
secid:weakness/owasp/top10@2021#A01        # 2021 edition
secid:weakness/owasp/top10@2017#A01        # 2017 edition (different!)
secid:control/iso/27001@2022#A.8.1         # ISO 27001:2022
secid:control/iso/27001@2013#A.8.1         # ISO 27001:2013
```

#### Versionless References

When version is omitted, assume "current" or "latest":
```
secid:control/csa/ccm#IAM-12               # Current CCM version
secid:weakness/owasp/top10#A03             # Current Top 10
```

### 5.2 Qualifiers (`?key=value`)

Optional context that doesn't change identity:

```
secid:control/cloudflare/waf?surface=api   # API-specific context
secid:advisory/nist/nvd#CVE-2024-1234?lang=ja   # Japanese translation
```

Qualifiers never define identity - two SecIDs differing only in qualifiers refer to the same thing with different context.

### 5.3 Subpath (`#subpath`)

Addressable parts inside the thing. Use subpath to reference **structural components** within a document. Subpaths can use `/` for hierarchical depth.

#### Subpath Conventions by Type

**Regulations - Legal Citations:**
```
# Articles (using / for hierarchy)
secid:regulation/eu/gdpr#art-32            # Article 32
secid:regulation/eu/gdpr#art-32/1          # Article 32, paragraph 1
secid:regulation/eu/gdpr#art-32/1/a        # Article 32(1)(a)
secid:regulation/eu/gdpr#art-32/1/a/ii     # Article 32(1)(a)(ii)

# Chapters and Sections
secid:regulation/eu/gdpr#chapter-4         # Chapter IV
secid:regulation/eu/gdpr#recital-78        # Recital 78

# US Code Style
secid:regulation/us/hipaa#164.312          # 45 CFR 164.312
secid:regulation/us/hipaa#164.312/a/1      # 164.312(a)(1)
secid:regulation/us/hipaa#164.312/a/2/iv   # 164.312(a)(2)(iv)

# Sections
secid:regulation/us/sox#section-302        # Section 302
secid:regulation/us/sox#section-404        # Section 404
```

**Controls - Guidance Sections:**
```
# CCM control guidance (framework is name, control is subpath)
secid:control/csa/ccm@4.0#IAM-12
secid:control/csa/ccm@4.0#IAM-12/audit-guidance
secid:control/csa/ccm@4.0#IAM-12/implementation-guidance
secid:control/csa/aicm@1.0#INP-01/Auditing%20Guidelines

# NIST sections
secid:control/nist/csf@2.0#PR.AC-1
secid:control/nist/csf@2.0#PR.AC-1/examples
secid:control/nist/csf@2.0#PR.AC-1/informative-references

# ISO control parts
secid:control/iso/27001@2022#A.8.1
secid:control/iso/27001@2022#A.8.1/purpose
secid:control/iso/27001@2022#A.8.1/guidance
```

**Advisories - Multiple CVEs in One Advisory:**
```
# Red Hat advisory covering multiple CVEs
secid:advisory/redhat/errata#RHSA-2024:1234#CVE-2024-1111
secid:advisory/redhat/errata#RHSA-2024:1234#CVE-2024-2222
secid:advisory/redhat/errata#RHSA-2024:1234#CVE-2024-3333

# Debian advisory sections
secid:advisory/debian/dsa#DSA-5678-1#CVE-2024-1234

# GHSA with multiple affected packages
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz#npm
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz#pip
```

**Weaknesses - Structural Sections:**
```
# CWE sections
secid:weakness/mitre/cwe#CWE-79#extended-description
secid:weakness/mitre/cwe#CWE-79#potential-mitigations
secid:weakness/mitre/cwe#CWE-79#detection-methods
secid:weakness/mitre/cwe#CWE-79#observed-examples

# OWASP Top 10 sections (framework is name, specific item is subpath)
secid:weakness/owasp/top10@2021#A03
secid:weakness/owasp/top10@2021#A03/description
secid:weakness/owasp/top10@2021#A03/how-to-prevent
secid:weakness/owasp/top10@2021#A03/example-attack-scenarios
```

**TTPs - Framework Sections:**
```
# ATT&CK technique sections
secid:ttp/mitre/attack#T1059#detection
secid:ttp/mitre/attack#T1059#mitigation
secid:ttp/mitre/attack#T1059#procedure-examples

# Sub-techniques (note: these are names, not subpaths)
secid:ttp/mitre/attack#T1059.003                 # This is the ID, not a subpath
secid:ttp/mitre/attack#T1059.003#detection       # Section within sub-technique
```

**References - Document Sections:**
```
# Executive orders and policy documents
secid:reference/whitehouse/eo-14110#section-4/1   # AI EO section 4.1
secid:reference/whitehouse/eo-14110#section-4/2   # AI EO section 4.2
secid:reference/whitehouse/m-24-10#appendix-a     # OMB memo appendix

# Research paper sections
secid:reference/arxiv/2303.08774#section-3        # GPT-4 paper section
secid:reference/arxiv/2307.03109#appendix         # Jailbroken appendix
secid:reference/arxiv/2402.05369#methodology      # Sleeper Agents methodology
```

#### Subpath Naming Rules

1. Use lowercase with hyphens: `#implementation-guidance` not `#ImplementationGuidance`
2. Keep it short but descriptive: `#art-32` not `#article-number-32`
3. Mirror source structure when possible: use the document's own section names
4. Preserve upstream IDs: `#CVE-2024-1234` keeps the CVE format

### 5.4 Combined Version and Subpath

Version and subpath can be used together:

```
# Specific article in specific version
secid:regulation/eu/gdpr@2016-04-27#art-32/1/a

# Control guidance in framework version
secid:control/csa/ccm@4.0#IAM-12/audit-guidance

# Specific section in dated release
secid:weakness/owasp/top10@2021#A03/how-to-prevent

# ISO control guidance in specific year
secid:control/iso/27001@2022#A.8.1/implementation-guidance
```

## 6. Future Layers: Relationships and Overlays

**Identifiers are just identifiers.** This specification defines how to write SecID strings. What you can say *about* SecIDs - relationships between them, enrichments, corrections - belongs in separate data layers.

### Planned Layers

| Layer | Purpose | Status |
|-------|---------|--------|
| **Relationships** | Connect SecIDs (aliases, enriches, mitigates, etc.) | Planned - see [RELATIONSHIPS.md](RELATIONSHIPS.md) |
| **Overlays** | Add metadata without modifying sources | Planned - see [OVERLAYS.md](OVERLAYS.md) |

### Why Deferred?

These layers involve design decisions that benefit from real-world usage:

- Relationship directionality and cardinality
- Conflict resolution between assertions
- Provenance and authority tracking
- Storage formats and query patterns

Rather than design these upfront, we're building the identifier system and registry first. Usage will inform the data layer design.


## 7. Namespace Definition Format

Namespace files use Obsidian-style format: YAML frontmatter + Markdown body.

### 7.1 Frontmatter (Structured Data)

```yaml
---
# What type this namespace belongs to
type: "advisory"
namespace: "redhat"

# Human-readable names
common_name: "Red Hat Security"
full_name: "Red Hat Product Security"

# Resolution
urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"

# ID routing - how to parse and resolve <name> patterns
id_routing:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "Red Hat CVE Database"
    url_template: "https://access.redhat.com/security/cve/{id}"
  - pattern: "RHSA-\\d{4}:\\d+"
    system: "Red Hat Security Advisory"
    url_template: "https://access.redhat.com/errata/{id}"
  - pattern: "RHBA-\\d{4}:\\d+"
    system: "Red Hat Bug Advisory"
    url_template: "https://access.redhat.com/errata/{id}"
  - pattern: "\\d{7}"
    system: "Bugzilla"
    url_template: "https://bugzilla.redhat.com/show_bug.cgi?id={id}"

# Examples
examples:
  - "secid:advisory/redhat/cve#CVE-2024-1234"
  - "secid:advisory/redhat/errata#RHSA-2024:1234"

status: "active"
---
```

### 7.2 Markdown Body (Rich Context)

The body contains human/AI-readable context:

- **What It Is** - Description of this namespace
- **ID Formats** - Detailed explanation of name patterns
- **Resolution** - How to look up identifiers
- **Caveats** - Important gotchas, edge cases
- **Recent Developments** - Current events, changes

## 8. Normalization Rules

### 8.1 String Normalization

- Lowercase type and namespace: `secid:advisory/mitre/cve#...`
- Preserve case in name when it's an upstream ID: `CVE-2024-1234` not `cve-2024-1234`
- Remove special characters from namespaces: `ATT&CK` → `attack`
- Hyphens allowed for multi-word names: `llm-top10`
- Type and namespace use only lowercase letters, numbers, and hyphens

### 8.2 Percent Encoding

SecID must support a wide variety of upstream identifiers and names - including those with spaces, special characters, and Unicode. Files must work across all operating systems (Windows, macOS, Linux) and be safe in shell environments. The approach: percent-encode special characters for safe storage and transport, then render human-friendly for display.

**Unicode support:** SecID names and filenames support full Unicode. Non-ASCII characters are percent-encoded as UTF-8 bytes (e.g., `é` → `%C3%A9`). This ensures cross-platform filesystem compatibility while preserving international characters.

#### Characters That Must Be Encoded

**SecID Structural Characters** - These have special meaning in SecID syntax and must always be encoded when used literally in names or subpaths:

| Character | Encoded | SecID Meaning |
|-----------|---------|---------------|
| `:` | `%3A` | Scheme separator (`secid:`) |
| `/` | `%2F` | Path separator (type/namespace/name) |
| `@` | `%40` | Version prefix |
| `?` | `%3F` | Qualifier prefix |
| `#` | `%23` | Subpath prefix |
| `%` | `%25` | Encoding escape character |

**URL Reserved Characters** - Per RFC 3986, these have special meaning in URLs and should be encoded:

| Character | Encoded | Notes |
|-----------|---------|-------|
| `&` | `%26` | Query parameter separator |
| `=` | `%3D` | Query key-value separator |
| `+` | `%2B` | Sometimes interpreted as space |
| `;` | `%3B` | Parameter separator |
| `[` | `%5B` | IPv6 address delimiter |
| `]` | `%5D` | IPv6 address delimiter |
| `{` | `%7B` | URI template syntax |
| `}` | `%7D` | URI template syntax |
| `!` | `%21` | Sub-delimiter |
| `'` | `%27` | Sub-delimiter |
| `(` | `%28` | Sub-delimiter |
| `)` | `%29` | Sub-delimiter |
| `*` | `%2A` | Sub-delimiter |
| `,` | `%2C` | Sub-delimiter |

**Filesystem Invalid Characters** - These are invalid in filenames on one or more operating systems:

| Character | Encoded | Invalid On |
|-----------|---------|------------|
| `\` | `%5C` | Path separator on Windows |
| `<` | `%3C` | Windows |
| `>` | `%3E` | Windows |
| `"` | `%22` | Windows |
| `\|` | `%7C` | Windows |
| `*` | `%2A` | Windows |
| `?` | `%3F` | Windows |
| `:` | `%3A` | Windows (except after drive letter) |

**Shell-Sensitive Characters** - These have special meaning in shell environments and should be encoded to prevent unexpected behavior:

| Character | Encoded | Shell Risk |
|-----------|---------|------------|
| `$` | `%24` | Variable expansion |
| `` ` `` | `%60` | Command substitution |
| `!` | `%21` | History expansion (bash) |
| `~` | `%7E` | Home directory expansion |
| `^` | `%5E` | History substitution, regex |
| Space | `%20` | Argument separator |
| Tab | `%09` | Whitespace |
| Newline | `%0A` | Command separator |

**Other Characters to Encode:**

| Character | Encoded | Notes |
|-----------|---------|-------|
| `\`` | `%5C%60` | Backtick (command substitution) |
| `"` | `%22` | Quote character |
| `'` | `%27` | Quote character |

#### Examples

```
A&A-01                    → A%26A-01
INP-01 (Draft)            → INP-01%20%28Draft%29
Price: $100               → Price%3A%20%24100
File[1]                   → File%5B1%5D
{template}                → %7Btemplate%7D
```

#### Summary: Always Encode These

For maximum compatibility across URLs, filesystems, and shells, encode these characters in names and subpaths:

```
Space  &  =  +  ;  [  ]  {  }  !  '  (  )  *  ,
:  /  @  ?  #  %  \  <  >  "  |  $  `  ~  ^
```

Tools should render identifiers human-friendly for display while storing the encoded form.

**Filename encoding:** When using SecIDs as filenames, encode all characters invalid on the target filesystem. For cross-platform compatibility, encode all characters listed above. The full SecID `secid:advisory/mitre/cve#CVE-2024-1234` becomes `secid%3Aadvisory%2Fmitre%2Fcve%23CVE-2024-1234` as a filename.

### 8.3 Canonical Form

All SecIDs should normalize to:
```
secid:type/namespace/name[@version][?qualifiers][#subpath]
```

Display shorthands must expand to canonical form for storage and comparison.

## 9. Design Principles

1. **Identifiers are just identifiers** - Registry defines what exists; relationships and enrichment are separate future layers
2. **Identifier, not locator** - SecID identifies things; resolution is separate
3. **Identity ≠ authority** - Identifiers don't imply trust or correctness
4. **Guidelines, not rules** - Human/AI readable, some messiness OK
5. **PURL compatibility** - Same mental model, similar grammar

### 9.1 The Three Layers

SecID separates concerns into three layers:

| Layer | Purpose | Status |
|-------|---------|--------|
| **Registry** | Defines namespaces, ID patterns, resolution | Current (`registry/`) |
| **Relationships** | Connections between identifiers | Future (see [RELATIONSHIPS.md](RELATIONSHIPS.md)) |
| **Overlays** | Corrections, enrichments, warnings | Future (see [OVERLAYS.md](OVERLAYS.md)) |

The registry is definitional: "what identifiers exist and how to resolve them." It doesn't track history, state changes, or connections - those will belong in relationship and overlay layers once designed.

## 10. Repository Structure

SecID is a single repository containing specification and registry. **One file per namespace** contains all sources for that namespace:

```
secid/
├── README.md              # Project overview
├── SPEC.md                # This specification
├── DESIGN-DECISIONS.md    # Key decisions and rationale
├── STRATEGY.md            # Adoption and governance
├── ROADMAP.md             # Implementation phases
├── USE-CASES.md           # Concrete examples
├── RELATIONSHIPS.md       # Future layer (exploratory)
├── OVERLAYS.md            # Future layer (exploratory)
├── registry/              # Namespace definitions
│   ├── advisory.md        # Type definition (what is an advisory?)
│   ├── advisory/          # Advisory namespaces
│   │   ├── mitre.md       # MITRE: cve
│   │   ├── nist.md        # NIST: nvd
│   │   ├── github.md      # GitHub: ghsa
│   │   └── redhat.md      # Red Hat: cve, errata, bugzilla (ALL IN ONE)
│   ├── weakness.md        # Type definition (what is a weakness?)
│   ├── weakness/
│   │   ├── mitre.md       # MITRE: cwe
│   │   └── owasp.md       # OWASP: top10, llm-top10, etc. (ALL IN ONE)
│   ├── ttp.md             # Type definition
│   ├── ttp/
│   │   └── mitre.md       # MITRE: attack, atlas, capec (ALL IN ONE)
│   ├── control.md         # Type definition
│   ├── control/
│   │   ├── nist.md        # NIST: csf, 800-53, ai-rmf (ALL IN ONE)
│   │   ├── iso.md         # ISO: 27001, 27002 (ALL IN ONE)
│   │   └── cis.md         # CIS: controls, benchmarks
│   ├── entity.md          # Type definition
│   ├── entity/
│   │   ├── mitre.md       # MITRE organization
│   │   ├── nist.md        # NIST organization
│   │   └── redhat.md      # Red Hat organization
│   ├── regulation.md      # Type definition
│   ├── regulation/
│   │   └── eu.md          # EU: gdpr, ai-act, nis2 (ALL IN ONE)
│   ├── reference.md       # Type definition
│   └── reference/
│       └── whitehouse.md  # White House: executive orders
└── seed/                  # Seed data for bulk import
    └── *.csv
```

