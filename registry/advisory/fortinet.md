---
type: advisory
namespace: fortinet
full_name: "Fortinet, Inc."
operator: "secid:entity/fortinet"
website: "https://www.fortinet.com"
status: active

sources:
  fsa:
    full_name: "Fortinet Security Advisory"
    urls:
      website: "https://www.fortiguard.com/psirt"
      lookup: "https://www.fortiguard.com/psirt/{id}"
    id_pattern: "FG-IR-\\d{2}-\\d{3}"
    examples:
      - "secid:advisory/fortinet/fsa#FG-IR-24-001"
      - "secid:advisory/fortinet/fsa#FG-IR-23-097"
---

# Fortinet Advisory Sources

Fortinet is a cybersecurity company specializing in network security appliances, particularly firewalls. FortiGate is one of the most deployed enterprise firewalls globally.

## Why Fortinet Matters for Security

Fortinet devices protect network perimeters:

- **FortiGate** - Next-generation firewall appliances
- **FortiOS** - Operating system for Fortinet devices
- **FortiManager** - Centralized management
- **FortiAnalyzer** - Logging and analytics
- **FortiClient** - Endpoint protection

Fortinet vulnerabilities are high-value targets because firewalls sit at network boundaries with access to internal networks.

## Advisory ID Format

Fortinet uses FG-IR-YY-NNN format:
```
FG-IR-23-097  (year 2023, advisory 097)
FG-IR-24-001  (year 2024, advisory 001)
```

## Security Track Record

Fortinet devices have been targeted by:
- Nation-state actors (APT groups)
- Ransomware operators
- Initial access brokers

Critical FortiOS vulnerabilities frequently appear in CISA KEV.

## Notes

- Fortinet is a CVE Numbering Authority (CNA)
- FortiGuard Labs publishes threat research alongside PSIRT advisories
- SSL-VPN vulnerabilities are particularly high-risk (internet-exposed)

---

## fsa

Fortinet's PSIRT advisories.

### Format

```
secid:advisory/fortinet/fsa#FG-IR-YY-NNN
```

Two-digit year and three-digit sequential number.

### Resolution

```
secid:advisory/fortinet/fsa#FG-IR-23-097
  -> https://www.fortiguard.com/psirt/FG-IR-23-097
```

### Notes

- Covers FortiOS, FortiGate, FortiManager, FortiAnalyzer, etc.
- Fortinet products are high-value targets; advisories often critical
