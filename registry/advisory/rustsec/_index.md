---
namespace: rustsec
full_name: "RustSec Advisory Database"
website: "https://rustsec.org"
type: opensource
founded: 2017
operator: "RustSec Working Group"
---

# RustSec Advisory Database

RustSec is a community-driven security advisory database for the Rust ecosystem. It tracks vulnerabilities and security issues in Rust crates (packages) published to crates.io.

## Why RustSec Matters for Security

Rust is growing in security-critical software:

- **Memory safety** - Rust's guarantees don't prevent all vulnerabilities
- **Systems programming** - Replacing C/C++ in security-sensitive code
- **Security tools** - Increasing number of security tools written in Rust
- **Infrastructure** - Cloudflare, Discord, Dropbox use Rust

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `advisories` | RustSec Advisory Database | RUSTSEC-2024-0001 |

## RUSTSEC ID Format

RustSec advisories use RUSTSEC- prefix:
```
RUSTSEC-2024-0001  (year 2024, advisory 0001)
RUSTSEC-2023-0071  (year 2023, advisory 0071)
```

## cargo-audit

RustSec provides official tooling:

```bash
cargo install cargo-audit
cargo audit
```

cargo-audit checks your Cargo.lock against the RustSec database.

## Advisory Categories

RustSec tracks several categories:
- **Vulnerabilities** - Security issues
- **Unmaintained crates** - Abandoned packages (security risk)
- **Informational** - Security-relevant but not vulnerabilities

## Relationship to OSV

RustSec advisories are indexed in Google's OSV database:
```
https://osv.dev/vulnerability/RUSTSEC-2024-0001
```

## Notes

- Advisory database at github.com/rustsec/advisory-db
- Advisories use TOML format (human and machine readable)
- Rust's safety guarantees prevent some bug classes but not all
