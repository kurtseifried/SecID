---
type: advisory
namespace: oracle
name: alert
full_name: "Oracle Security Alert"
operator: "secid:entity/oracle"

urls:
  website: "https://www.oracle.com/security-alerts/"
  lookup: "https://www.oracle.com/security-alerts/alert-{id}.html"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/oracle/alert#CVE-2024-1234"
  - "secid:advisory/oracle/alert#CVE-2021-44228"

status: active
---

# Oracle Security Alert

Oracle's out-of-band security alerts for critical vulnerabilities.

## Format

```
secid:advisory/oracle/alert#CVE-YYYY-NNNN
```

## Resolution

```
secid:advisory/oracle/alert#CVE-2021-44228
  → https://www.oracle.com/security-alerts/alert-cve-2021-44228.html
```

## Notes

- Security Alerts are issued outside the regular CPU schedule
- Used for critical vulnerabilities requiring immediate attention
- For quarterly updates, see `secid:advisory/oracle/cpu`
