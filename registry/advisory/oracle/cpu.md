---
type: advisory
namespace: oracle
name: cpu
full_name: "Oracle Critical Patch Update"
operator: "secid:entity/oracle"

urls:
  website: "https://www.oracle.com/security-alerts/"
  lookup: "https://www.oracle.com/security-alerts/cpujan{year}.html"

id_pattern: "(jan|apr|jul|oct)\\d{4}"

examples:
  - "secid:advisory/oracle/cpu#jan2024"
  - "secid:advisory/oracle/cpu#oct2023"
  - "secid:advisory/oracle/cpu#apr2024"

status: active
---

# Oracle Critical Patch Update (CPU)

Oracle's quarterly security patch releases.

## Format

```
secid:advisory/oracle/cpu#MMMYYYY
```

Month (jan, apr, jul, oct) and year. CPUs are released quarterly.

## Resolution

```
secid:advisory/oracle/cpu#jan2024
  → https://www.oracle.com/security-alerts/cpujan2024.html

secid:advisory/oracle/cpu#oct2023
  → https://www.oracle.com/security-alerts/cpuoct2023.html
```

## Schedule

Oracle releases CPUs quarterly:
- January
- April
- July
- October

## Notes

- CPUs bundle many CVE fixes across Oracle products
- Each CPU contains fixes for multiple product families
- For individual CVE alerts, see `secid:advisory/oracle/alert`
