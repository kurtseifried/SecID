---
namespace: govinfo.gov
full_name: "United States Federal"
type: regulation

urls:
  website: "https://www.govinfo.gov"
  lookup_cfr: "https://www.ecfr.gov/current/title-{title}/part-{part}"

examples:
  - "hipaa"
  - "glba"
  - "fisma"
  - "ferpa"

status: active
---

# US Federal Namespace

United States federal laws and regulations.

## Format

```
secid:regulation/govinfo.gov/{law}
secid:regulation/govinfo.gov/hipaa#164.312
```

## Key Regulations

| ID | Full Name | Primary Domain |
|----|-----------|----------------|
| hipaa | Health Insurance Portability and Accountability Act | Healthcare |
| glba | Gramm-Leach-Bliley Act | Financial |
| sox | Sarbanes-Oxley Act | Financial/Corporate |
| fisma | Federal Information Security Management Act | Federal IT |
| ferpa | Family Educational Rights and Privacy Act | Education |
| coppa | Children's Online Privacy Protection Act | Children's Privacy |
| ecpa | Electronic Communications Privacy Act | Communications |
| cfaa | Computer Fraud and Abuse Act | Computer Crime |

## Subpaths (HIPAA example)

```
secid:regulation/govinfo.gov/hipaa#164.312        # 45 CFR 164.312
secid:regulation/govinfo.gov/hipaa#164.312.a.1    # Technical safeguards
secid:regulation/govinfo.gov/hipaa#164.312.a.2.iv # Encryption
```

## Notes

- Federal laws apply nationally
- See `us-XX` namespaces for state laws
- CFR citations use standard format
