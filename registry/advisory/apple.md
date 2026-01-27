---
type: advisory
namespace: apple
full_name: "Apple Inc."
operator: "secid:entity/apple"
website: "https://www.apple.com"
status: active

sources:
  ht:
    full_name: "Apple Security Update (HT)"
    urls:
      website: "https://support.apple.com/en-us/HT201222"
      lookup: "https://support.apple.com/{id}"
    id_pattern: "HT\\d{6}"
    examples:
      - "secid:advisory/apple/ht#HT214036"
      - "secid:advisory/apple/ht#HT213931"
---

# Apple Advisory Sources

Apple is a technology company producing Mac computers, iPhone, iPad, and associated software. Apple Product Security handles vulnerability response for all Apple platforms.

## Why Apple Matters for Security

Apple's ecosystem is vast:

- **iOS/iPadOS** - Mobile operating system, ~1.5 billion active devices
- **macOS** - Desktop operating system
- **Safari** - Web browser (WebKit engine, also used by all iOS browsers)
- **watchOS/tvOS/visionOS** - Wearable and TV platforms

Apple vulnerabilities are high-value targets for nation-states and commercial spyware vendors.

## Advisory Format

Apple publishes security content as HT (Help Topic) support articles:
```
https://support.apple.com/HT214036
```

Each HT article corresponds to a software release and lists all CVEs fixed in that release. Apple bundles many CVEs per release.

## Security Characteristics

- **Coordinated releases** - Security fixes ship with OS/app updates
- **Limited details** - Apple provides minimal vulnerability details until fixes ship
- **Bug bounty** - Apple Security Research bounty program
- **Zero-days** - Apple iOS zero-days are among the most valuable ($1M+)

## Notes

- Apple is a CVE Numbering Authority (CNA)
- Apple delays CVE details until patches are available
- Safari/WebKit vulnerabilities affect all iOS browsers (Apple policy)
- Pegasus spyware notably exploited Apple zero-days

---

## ht

Apple's security update documentation.

### Format

```
secid:advisory/apple/ht#HTNNNNNN
```

### Resolution

```
secid:advisory/apple/ht#HT214036
  -> https://support.apple.com/HT214036
```

### Notes

- HT articles document security content of updates
- Covers iOS, iPadOS, macOS, watchOS, tvOS, Safari, etc.
- Apple bundles many CVEs per release
- See also Apple Security Research for bounty program
