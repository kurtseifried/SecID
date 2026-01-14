---
namespace: google
full_name: "Google LLC (Alphabet)"
website: "https://www.google.com"
type: corporation
founded: 1998
headquarters: "Mountain View, California, USA"
parent: "Alphabet Inc."
---

# Google (Alphabet)

Google is one of the world's largest technology companies, operating search, cloud (GCP), Android, Chrome, and many other products. Google has multiple security teams handling different products.

## Why Google Matters for Security

Google's products are ubiquitous:

- **Chrome** - Dominant web browser (~65% market share)
- **Android** - Dominant mobile OS (~70% market share)
- **GCP** - Major cloud platform
- **OSV** - Open Source Vulnerabilities database
- **Project Zero** - Elite vulnerability research team

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `osv` | Open Source Vulnerabilities | PYSEC-2024-1, GO-2024-2887 |
| `chrome` | Chrome Security Releases | CVE-2024-0519 |
| `android` | Android Security Bulletins | 2024-01-01 |
| `gcp-bulletins` | GCP Security Bulletins | GCP-2024-001 |
| `project-zero` | Project Zero Issues | 2374 |

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
