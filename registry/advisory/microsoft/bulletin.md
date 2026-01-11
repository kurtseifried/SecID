---
type: advisory
namespace: microsoft
name: bulletin
full_name: "Microsoft Security Bulletin (Deprecated)"
operator: "secid:entity/microsoft"

urls:
  website: "https://docs.microsoft.com/en-us/security-updates/"
  lookup: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/{year}/{id}"

id_pattern: "MS\\d{2}-\\d{3}"

examples:
  - "secid:advisory/microsoft/bulletin#MS17-010"
  - "secid:advisory/microsoft/bulletin#MS08-067"

status: deprecated
deprecated_by: "secid:advisory/microsoft/msrc"
deprecated_date: "2017-01"
---

# Microsoft Security Bulletin (Deprecated)

Legacy Microsoft security bulletin format, discontinued in 2017.

## Format

```
secid:advisory/microsoft/bulletin#MSYY-NNN
```

Two-digit year and three-digit sequential number.

## Resolution

```
secid:advisory/microsoft/bulletin#MS17-010
  → https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010

secid:advisory/microsoft/bulletin#MS08-067
  → https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067
```

## Notes

- **Deprecated since January 2017** - Microsoft moved to MSRC Security Update Guide
- Still widely referenced (MS17-010 = EternalBlue, MS08-067 = Conficker)
- Historical bulletins remain accessible
- For current advisories, use `secid:advisory/microsoft/msrc`
