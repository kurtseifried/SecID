---
type: advisory
namespace: rustsec
full_name: "RustSec Advisory Database"
operator: "secid:entity/rustsec"
website: "https://rustsec.org"
status: active

sources:
  advisories:
    full_name: "RustSec Advisory Database"
    urls:
      website: "https://rustsec.org"
      api: "https://rustsec.org/advisories"
      bulk_data: "https://github.com/rustsec/advisory-db"
      lookup: "https://rustsec.org/advisories/{id}"
    id_pattern: "RUSTSEC-\\d{4}-\\d+"
    examples:
      - "secid:advisory/rustsec/advisories#RUSTSEC-2024-0001"
      - "secid:advisory/rustsec/advisories#RUSTSEC-2023-0071"
---

# RustSec Advisory Sources

RustSec is a community-driven security advisory database for the Rust ecosystem. It tracks vulnerabilities and security issues in Rust crates (packages) published to crates.io.

## Why RustSec Matters for Security

Rust is growing in security-critical software:

- **Memory safety** - Rust's guarantees don't prevent all vulnerabilities
- **Systems programming** - Replacing C/C++ in security-sensitive code
- **Security tools** - Increasing number of security tools written in Rust
- **Infrastructure** - Cloudflare, Discord, Dropbox use Rust

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

---

## advisories

Security advisories for Rust crates, maintained by the RustSec organization.

### Format

```
secid:advisory/rustsec/advisories#RUSTSEC-YYYY-NNNN
```

### Resolution

```
https://rustsec.org/advisories/{id}
```

### Why RustSec Matters

Rust is increasingly used for security-critical software:
- **Memory safety** - Rust's guarantees don't prevent all vulnerabilities
- **cargo audit** - Built-in vulnerability checking
- **Growing ecosystem** - More security tools written in Rust
- **Systems programming** - Replacing C/C++ in security-sensitive code

### Key Features

- **Unmaintained crate warnings** - Flags abandoned packages
- **Informational advisories** - Not all are vulnerabilities
- **TOML format** - Human and machine readable
- **cargo-audit integration** - `cargo audit` checks against this database

### Related Sources

- **OSV** - RUSTSEC advisories included in OSV
- **crates.io** - Rust package registry

### Notes

- RUSTSEC IDs assigned by RustSec working group
- Categories include: code-execution, crypto, denial-of-service, memory-corruption
- Important for supply chain security in Rust ecosystem
