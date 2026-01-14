---
type: advisory
namespace: rustsec
name: advisories
full_name: "RustSec Advisory Database"
operator: "secid:entity/rustsec"

urls:
  website: "https://rustsec.org"
  api: "https://rustsec.org/advisories"
  bulk_data: "https://github.com/rustsec/advisory-db"
  lookup: "https://rustsec.org/advisories/{id}"

id_pattern: "RUSTSEC-\\d{4}-\\d+"
examples:
  - "secid:advisory/rustsec/advisories#RUSTSEC-2024-0001"
  - "secid:advisory/rustsec/advisories#RUSTSEC-2023-0071"

status: active
---

# RustSec Advisory Database

Security advisories for Rust crates, maintained by the RustSec organization.

## Format

```
secid:advisory/rustsec/advisories#RUSTSEC-YYYY-NNNN
```

## Resolution

```
https://rustsec.org/advisories/{id}
```

## Why RustSec Matters

Rust is increasingly used for security-critical software:
- **Memory safety** - Rust's guarantees don't prevent all vulnerabilities
- **cargo audit** - Built-in vulnerability checking
- **Growing ecosystem** - More security tools written in Rust
- **Systems programming** - Replacing C/C++ in security-sensitive code

## Key Features

- **Unmaintained crate warnings** - Flags abandoned packages
- **Informational advisories** - Not all are vulnerabilities
- **TOML format** - Human and machine readable
- **cargo-audit integration** - `cargo audit` checks against this database

## Related Sources

- **OSV** - RUSTSEC advisories included in OSV
- **crates.io** - Rust package registry

## Notes

- RUSTSEC IDs assigned by RustSec working group
- Categories include: code-execution, crypto, denial-of-service, memory-corruption
- Important for supply chain security in Rust ecosystem
