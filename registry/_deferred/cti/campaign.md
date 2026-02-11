---
namespace: campaign
full_name: "Campaigns"
type: cti
subtype: campaign

examples:
  - "solarwinds-2020"
  - "colonial-pipeline"
  - "log4shell-exploitation"

status: active
---

# Campaign Namespace

Named attack campaigns and operations.

## Format

```
secid:cti/campaign/{name}
secid:cti/campaign/solarwinds-2020
```

## Naming Conventions

Use lowercase, hyphenated descriptive names:
- Include year when relevant: `solarwinds-2020`
- Use common name: `colonial-pipeline`
- For exploit campaigns: `log4shell-exploitation`

## Notable Campaigns

| ID | Description | Year |
|----|-------------|------|
| solarwinds-2020 | SolarWinds supply chain attack | 2020 |
| colonial-pipeline | Colonial Pipeline ransomware | 2021 |
| log4shell-exploitation | Log4j exploitation wave | 2021-2022 |
| kaseya-revil | Kaseya VSA ransomware | 2021 |

## Relationships

```
secid:cti/campaign/solarwinds-2020 → attributed_to → secid:cti/actor/apt29
secid:cti/campaign/solarwinds-2020 → exploited → secid:advisory/mitre.org/cve#CVE-2020-10148
```

## Notes

- Campaigns are time-bounded operations
- May involve multiple actors or techniques
- Link to CVEs exploited, actors involved
