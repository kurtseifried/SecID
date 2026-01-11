---
type: advisory
namespace: fortinet
name: fsa
full_name: "Fortinet Security Advisory"
operator: "secid:entity/fortinet"

urls:
  website: "https://www.fortiguard.com/psirt"
  lookup: "https://www.fortiguard.com/psirt/{id}"

id_pattern: "FG-IR-\\d{2}-\\d{3}"

examples:
  - "secid:advisory/fortinet/fsa#FG-IR-24-001"
  - "secid:advisory/fortinet/fsa#FG-IR-23-097"

status: active
---

# Fortinet Security Advisory (FG-IR)

Fortinet's PSIRT advisories.

## Format

```
secid:advisory/fortinet/fsa#FG-IR-YY-NNN
```

Two-digit year and three-digit sequential number.

## Resolution

```
secid:advisory/fortinet/fsa#FG-IR-23-097
  → https://www.fortiguard.com/psirt/FG-IR-23-097
```

## Notes

- Covers FortiOS, FortiGate, FortiManager, FortiAnalyzer, etc.
- Fortinet products are high-value targets; advisories often critical
