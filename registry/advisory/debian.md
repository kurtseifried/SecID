---
type: advisory
namespace: debian
full_name: "Debian Project"
operator: "secid:entity/debian"
website: "https://www.debian.org"
status: active

sources:
  dsa:
    full_name: "Debian Security Advisory"
    urls:
      website: "https://www.debian.org/security/"
      lookup: "https://www.debian.org/security/{year}/dsa-{num}"
    id_pattern: "DSA-\\d+-\\d+"
    examples:
      - "secid:advisory/debian/dsa#DSA-5678-1"
      - "secid:advisory/debian/dsa#DSA-5432-2"
  dla:
    full_name: "Debian LTS Advisory"
    urls:
      website: "https://www.debian.org/lts/security/"
      lookup: "https://www.debian.org/lts/security/{year}/dla-{num}"
    id_pattern: "DLA-\\d+-\\d+"
    examples:
      - "secid:advisory/debian/dla#DLA-1234-1"
      - "secid:advisory/debian/dla#DLA-3456-2"
  tracker:
    full_name: "Debian Security Tracker"
    urls:
      website: "https://security-tracker.debian.org/tracker"
      lookup: "https://security-tracker.debian.org/tracker/{id}"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/debian/tracker#CVE-2024-1234"
      - "secid:advisory/debian/tracker#CVE-2023-44487"
  bts:
    full_name: "Debian Bug Tracking System"
    urls:
      website: "https://bugs.debian.org"
      lookup: "https://bugs.debian.org/{id}"
    id_pattern: "\\d+"
    examples:
      - "secid:advisory/debian/bts#1012345"
      - "secid:advisory/debian/bts#987654"
---

# Debian Advisory Sources

Debian is one of the oldest and most influential Linux distributions. It's the upstream for Ubuntu and many other distributions. Debian's security team maintains security updates for stable releases.

## Why Debian Matters for Security

Debian's influence is broad:

- **Direct usage** - Popular for servers, especially in Europe
- **Derivatives** - Ubuntu, Linux Mint, and 100+ distros are based on Debian
- **Stability focus** - Debian Stable is known for reliability
- **Security team** - Dedicated team handles security updates

## Advisory Types

- **DSA (Debian Security Advisory)** - For current stable release
- **DLA (Debian LTS Advisory)** - For extended support releases (community-supported)

Both use similar format: `DSA-NNNN-R` or `DLA-NNNN-R` where R is revision number.

## Security Tracker

Debian's Security Tracker (security-tracker.debian.org) shows CVE status across all Debian releases. It's useful for checking if/when a CVE is fixed in each release.

## Notes

- Debian is upstream for Ubuntu security advisories
- Debian Stable prioritizes stability over newest versions
- Security support varies by release (Stable vs LTS vs oldstable)

---

## dsa

Debian Security Advisories for stable Debian releases.

### Format

```
secid:advisory/debian/dsa#DSA-NNNN-N
```

The suffix (-1, -2, etc.) indicates the revision of the advisory.

### Resolution

```
secid:advisory/debian/dsa#DSA-5678-1
  -> https://www.debian.org/security/2024/dsa-5678
```

### Notes

- DSA advisories are for stable Debian releases
- For LTS releases, see `secid:advisory/debian/dla`
- For CVE tracking, see `secid:advisory/debian/tracker`

---

## dla

Debian LTS (Long Term Support) Advisories for extended support releases.

### Format

```
secid:advisory/debian/dla#DLA-NNNN-N
```

The suffix (-1, -2, etc.) indicates the revision of the advisory.

### Resolution

```
secid:advisory/debian/dla#DLA-1234-1
  -> https://www.debian.org/lts/security/2024/dla-1234
```

### Notes

- DLA advisories are for Debian LTS releases (extended support)
- For stable releases, see `secid:advisory/debian/dsa`
- For CVE tracking, see `secid:advisory/debian/tracker`

---

## tracker

Debian's CVE tracking system showing how CVEs affect Debian packages.

### Format

```
secid:advisory/debian/tracker#CVE-YYYY-NNNN
```

### Resolution

```
secid:advisory/debian/tracker#CVE-2024-1234
  -> https://security-tracker.debian.org/tracker/CVE-2024-1234
```

### Notes

- Shows CVE status across all Debian releases
- Links to related DSA/DLA advisories
- Includes affected package versions and fix status
- For official advisories, see `secid:advisory/debian/dsa` and `secid:advisory/debian/dla`

---

## bts

Debian's bug tracking system.

### Format

```
secid:advisory/debian/bts#NNNNNNN
```

### Resolution

```
secid:advisory/debian/bts#1012345
  -> https://bugs.debian.org/1012345
```

### Notes

- Security bugs are tracked with "security" tag
- Referenced in DSA/DLA advisories
- For official advisories, see `secid:advisory/debian/dsa` and `secid:advisory/debian/dla`
- For CVE status, see `secid:advisory/debian/tracker`
