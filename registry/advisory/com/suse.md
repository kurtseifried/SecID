---
type: advisory
namespace: suse.com
full_name: "SUSE"
operator: "secid:entity/suse.com"
website: "https://www.suse.com"
status: active

sources:
  suse-su:
    full_name: "SUSE Security Update"
    urls:
      website: "https://www.suse.com/security/cve/"
      lookup: "https://www.suse.com/security/cve/{id}/"
    id_pattern: "SUSE-SU-\\d{4}:\\d{4}-\\d+"
    examples:
      - "secid:advisory/suse.com/suse-su#SUSE-SU-2024:0001-1"
      - "secid:advisory/suse.com/suse-su#SUSE-SU-2023:4567-1"
  bugzilla:
    full_name: "SUSE Bugzilla"
    urls:
      website: "https://bugzilla.suse.com"
      lookup: "https://bugzilla.suse.com/show_bug.cgi?id={id}"
    id_patterns:
      - pattern: "\\d+"
        description: "Bug ID"
      - pattern: "CVE-\\d{4}-\\d{4,}"
        description: "CVE alias"
    examples:
      - "secid:advisory/suse.com/bugzilla#1234567"
      - "secid:advisory/suse.com/bugzilla#CVE-2024-1234"
---

# SUSE Advisory Sources

SUSE is a German enterprise Linux company producing SUSE Linux Enterprise (SLE) and sponsoring openSUSE. SUSE is popular in Europe and in SAP environments.

## Why SUSE Matters for Security

SUSE serves enterprise Linux needs:

- **SUSE Linux Enterprise Server (SLES)** - Enterprise Linux distribution
- **SUSE Linux Enterprise Desktop (SLED)** - Enterprise desktop
- **openSUSE** - Community distribution (Leap and Tumbleweed)
- **Rancher** - Kubernetes management (SUSE acquired Rancher Labs)

SUSE is particularly common in SAP deployments and European enterprises.

## Advisory ID Format

SUSE Security Updates use `SUSE-SU-YYYY:NNNN-R` format:
```
SUSE-SU-2024:0001-1  (year 2024, update 0001, revision 1)
```

## openSUSE vs SUSE Linux Enterprise

- **openSUSE Leap** - Binary-compatible with SLES, community-supported
- **openSUSE Tumbleweed** - Rolling release, latest packages
- **SLES/SLED** - Commercial support, longer lifecycle

Security updates are similar but support timelines differ.

## Notes

- SUSE is a CVE Numbering Authority (CNA)
- SUSE Bugzilla supports CVE aliases for lookup
- SUSE acquired Rancher Labs (Kubernetes) in 2020

---

## suse-su

SUSE Linux security updates.

### Format

```
secid:advisory/suse.com/suse-su#SUSE-SU-YYYY:NNNN-R
```

Year, sequential number, and revision.

### Resolution

```
secid:advisory/suse.com/suse-su#SUSE-SU-2024:0001-1
  -> https://www.suse.com/support/update/announcement/2024/suse-su-20240001-1/
```

### Notes

- Covers SUSE Linux Enterprise, openSUSE
- For CVE tracking, see `secid:advisory/suse.com/cve`
- For bug tracking, see `secid:advisory/suse.com/bugzilla`

---

## bugzilla

SUSE's bug tracking system.

### Format

```
secid:advisory/suse.com/bugzilla#NNNNNNN
secid:advisory/suse.com/bugzilla#CVE-YYYY-NNNN
```

Accepts numeric bug IDs or CVE aliases.

### Resolution

```
secid:advisory/suse.com/bugzilla#1234567
  -> https://bugzilla.suse.com/show_bug.cgi?id=1234567

secid:advisory/suse.com/bugzilla#CVE-2024-1234
  -> https://bugzilla.suse.com/show_bug.cgi?id=CVE-2024-1234
```

### Notes

- SUSE Bugzilla supports CVE aliases (redirects to tracking bug)
- Security bugs may be restricted until fixed
- For official updates, see `secid:advisory/suse.com/suse-su`
