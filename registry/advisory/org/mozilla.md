---
type: advisory
namespace: mozilla.org
full_name: "Mozilla Foundation / Mozilla Corporation"
operator: "secid:entity/mozilla.org"
website: "https://www.mozilla.org"
status: active

sources:
  mfsa:
    full_name: "Mozilla Foundation Security Advisory"
    urls:
      website: "https://www.mozilla.org/security/advisories/"
      lookup: "https://www.mozilla.org/security/advisories/mfsa{id}/"
    id_pattern: "\\d{4}-\\d{2}"
    examples:
      - "secid:advisory/mozilla.org/mfsa#2024-01"
      - "secid:advisory/mozilla.org/mfsa#2023-56"
  bugzilla:
    full_name: "Mozilla Bugzilla"
    urls:
      website: "https://bugzilla.mozilla.org"
      lookup: "https://bugzilla.mozilla.org/show_bug.cgi?id={id}"
    id_pattern: "\\d+"
    examples:
      - "secid:advisory/mozilla.org/bugzilla#1234567"
      - "secid:advisory/mozilla.org/bugzilla#1876543"
---

# Mozilla Advisory Sources

Mozilla is the nonprofit organization (and its subsidiary corporation) that develops Firefox, Thunderbird, and other open-source software. Mozilla pioneered many web security features.

## Why Mozilla Matters for Security

Mozilla develops critical internet software:

- **Firefox** - Major web browser (~3% market share, but security-focused users)
- **Thunderbird** - Email client
- **NSS (Network Security Services)** - Crypto library used by many projects
- **Rust** - Mozilla incubated the Rust programming language

Mozilla also runs security initiatives like the Mozilla Security Blog and bug bounty program.

## Advisory ID Format

MFSA (Mozilla Foundation Security Advisory) uses YYYY-NN format:
```
MFSA 2024-01  (first advisory of 2024)
MFSA 2023-56  (56th advisory of 2023)
```

Each MFSA typically corresponds to a Firefox/Thunderbird release and may contain multiple CVEs.

## Security Culture

Mozilla has a strong security culture:
- Regular security releases
- Active bug bounty program
- Security bugs restricted until fixes ship
- Detailed security advisories

## Notes

- Mozilla is a CVE Numbering Authority (CNA)
- Firefox ESR (Extended Support Release) is popular in enterprises
- NSS vulnerabilities can affect many non-Mozilla applications

---

## mfsa

Mozilla's official security advisories for Firefox, Thunderbird, and other products.

### Format

```
secid:advisory/mozilla.org/mfsa#YYYY-NN
```

Year and sequential number within that year.

### Resolution

```
secid:advisory/mozilla.org/mfsa#2024-01
  -> https://www.mozilla.org/security/advisories/mfsa2024-01/
```

### Notes

- MFSA advisories cover Firefox, Firefox ESR, Thunderbird, etc.
- Often bundle multiple CVEs per advisory (per release)
- For bug details, see `secid:advisory/mozilla.org/bugzilla`

---

## bugzilla

Mozilla's bug tracking system.

### Format

```
secid:advisory/mozilla.org/bugzilla#NNNNNNN
```

### Resolution

```
secid:advisory/mozilla.org/bugzilla#1234567
  -> https://bugzilla.mozilla.org/show_bug.cgi?id=1234567
```

### Notes

- Security bugs are often restricted until fixes ship
- Referenced in MFSA advisories
- For official advisories, see `secid:advisory/mozilla.org/mfsa`
