---
type: advisory
namespace: google
full_name: "Google LLC (Alphabet)"
operator: "secid:entity/google"
website: "https://www.google.com"
status: active

sources:
  osv:
    full_name: "Open Source Vulnerabilities"
    urls:
      website: "https://osv.dev"
      api: "https://api.osv.dev/v1"
      bulk_data: "https://osv-vulnerabilities.storage.googleapis.com"
      lookup: "https://osv.dev/vulnerability/{id}"
    id_patterns:
      - pattern: "PYSEC-\\d{4}-\\d+"
        ecosystem: "PyPI"
      - pattern: "RUSTSEC-\\d{4}-\\d+"
        ecosystem: "crates.io"
      - pattern: "GO-\\d{4}-\\d+"
        ecosystem: "Go"
      - pattern: "GHSA-.*"
        ecosystem: "GitHub"
    examples:
      - "secid:advisory/google/osv#PYSEC-2024-1"
      - "secid:advisory/google/osv#RUSTSEC-2024-0001"
      - "secid:advisory/google/osv#GO-2024-0001"
  chrome:
    full_name: "Chrome Security Release"
    urls:
      website: "https://chromereleases.googleblog.com/search/label/Stable%20updates"
      release_notes: "https://chromereleases.googleblog.com/"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/google/chrome#CVE-2024-0519"
      - "secid:advisory/google/chrome#CVE-2023-7024"
  android:
    full_name: "Android Security Bulletin"
    urls:
      website: "https://source.android.com/docs/security/bulletin"
      lookup: "https://source.android.com/docs/security/bulletin/{date}"
    id_patterns:
      - pattern: "CVE-\\d{4}-\\d{4,}"
        description: "CVE identifier"
      - pattern: "\\d{4}-\\d{2}-\\d{2}"
        description: "Bulletin date"
    examples:
      - "secid:advisory/google/android#2024-01-01"
      - "secid:advisory/google/android#CVE-2024-0031"
  gcp-bulletins:
    full_name: "Google Cloud Security Bulletins"
    urls:
      website: "https://cloud.google.com/support/bulletins"
      lookup: "https://cloud.google.com/support/bulletins#{id}"
    id_pattern: "GCP-\\d{4}-\\d+"
    examples:
      - "secid:advisory/google/gcp-bulletins#GCP-2024-001"
      - "secid:advisory/google/gcp-bulletins#GCP-2023-034"
  project-zero:
    full_name: "Google Project Zero"
    urls:
      website: "https://googleprojectzero.blogspot.com/"
      issues: "https://bugs.chromium.org/p/project-zero/issues/list"
      lookup: "https://bugs.chromium.org/p/project-zero/issues/detail?id={id}"
    id_pattern: "\\d+"
    examples:
      - "secid:advisory/google/project-zero#2374"
      - "secid:advisory/google/project-zero#1945"
---

# Google Advisory Sources

Google is one of the world's largest technology companies, operating search, cloud (GCP), Android, Chrome, and many other products. Google has multiple security teams handling different products.

## Why Google Matters for Security

Google's products are ubiquitous:

- **Chrome** - Dominant web browser (~65% market share)
- **Android** - Dominant mobile OS (~70% market share)
- **GCP** - Major cloud platform
- **OSV** - Open Source Vulnerabilities database
- **Project Zero** - Elite vulnerability research team

## OSV (Open Source Vulnerabilities)

OSV.dev is Google's aggregated vulnerability database for open-source packages. It:
- Aggregates from 30+ ecosystem databases
- Uses standardized OSV schema
- Provides API and tooling (osv-scanner)

OSV includes PYSEC (Python), RUSTSEC (Rust), GO- (Go), and many other ecosystem prefixes.

## Project Zero

Project Zero is Google's elite vulnerability research team. They:
- Research vulnerabilities across all vendors
- Follow 90-day disclosure deadlines
- Publish detailed technical writeups

## Notes

- Google is a CVE Numbering Authority (CNA)
- Android security bulletins are monthly
- Chrome releases frequently with security fixes
- Project Zero findings often make headlines

---

## osv

Google's aggregated open source vulnerability database.

### Format

```
secid:advisory/google/osv#{ecosystem-id}
```

### Resolution

```
https://osv.dev/vulnerability/{id}
```

### Ecosystems

OSV aggregates from multiple sources:
- PyPI (PYSEC-*)
- crates.io (RUSTSEC-*)
- Go (GO-*)
- npm (via GHSA)
- And many more

### Notes

- Ecosystem-specific IDs
- Standardized OSV schema
- Machine-readable format

---

## chrome

Google Chrome security updates.

### Format

```
secid:advisory/google/chrome#CVE-YYYY-NNNN
```

### Resolution

Chrome CVEs are documented in release blog posts:

```
secid:advisory/google/chrome#CVE-2024-0519
  -> Search chromereleases.googleblog.com
  -> https://crbug.com/{bug_id} (if public)
```

### Notes

- Chrome releases frequently with security fixes
- Many CVEs per release (listed in "Stable channel update" posts)
- Chromium bugs often restricted until fix ships
- `crbug.com` redirects to Chromium bug tracker
- Chrome vulnerabilities often exploited in the wild
- Security fixes documented in "Stable updates" labeled posts on the blog

---

## android

Google's monthly Android security bulletins.

### Format

```
secid:advisory/google/android#YYYY-MM-DD
secid:advisory/google/android#CVE-YYYY-NNNN
```

Monthly bulletins or specific CVEs.

### Resolution

```
secid:advisory/google/android#2024-01-01
  -> https://source.android.com/docs/security/bulletin/2024-01-01
```

### Notes

- Monthly security bulletins (released ~first Monday)
- Security patch levels (YYYY-MM-01 and YYYY-MM-05)
- Covers Android framework, kernel, vendor components
- OEMs ship patches at varying speeds

---

## gcp-bulletins

Official security advisories from Google Cloud Platform covering GCP services and infrastructure.

### Format

```
secid:advisory/google/gcp-bulletins#GCP-YYYY-NNN
```

### Resolution

```
https://cloud.google.com/support/bulletins#{id}
```

### Why GCP Bulletins Matter

Google Cloud is a major cloud provider:
- **GKE vulnerabilities** - Kubernetes and container security
- **Compute Engine** - VM and infrastructure issues
- **Service-specific** - Cloud SQL, BigQuery, etc.
- **Shared fate model** - Google's security responsibility clarity

### Related Sources

- **GKE Security Bulletins** - Kubernetes-specific advisories
- **Chrome/Android** - Separate advisory tracks (see google/chrome, google/android)

### Notes

- Bulletins often reference CVEs but include GCP-specific context
- Patch availability and timeline information included
- Some issues are GCP-specific without CVE assignment

---

## project-zero

Google's elite vulnerability research team.

### Format

```
secid:advisory/google/project-zero#NNNN
```

Project Zero issue number.

### Resolution

```
secid:advisory/google/project-zero#2374
  -> https://bugs.chromium.org/p/project-zero/issues/detail?id=2374
```

### Notes

- Researches vulnerabilities across all vendors
- 90-day disclosure deadline policy
- Often finds high-impact vulnerabilities
- Issues restricted until fixed or deadline expires
- Blog posts provide detailed technical analysis
