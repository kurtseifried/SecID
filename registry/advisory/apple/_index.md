---
namespace: apple
full_name: "Apple Inc."
website: "https://www.apple.com"
type: corporation
founded: 1976
headquarters: "Cupertino, California, USA"
---

# Apple Inc.

Apple is a technology company producing Mac computers, iPhone, iPad, and associated software. Apple Product Security handles vulnerability response for all Apple platforms.

## Why Apple Matters for Security

Apple's ecosystem is vast:

- **iOS/iPadOS** - Mobile operating system, ~1.5 billion active devices
- **macOS** - Desktop operating system
- **Safari** - Web browser (WebKit engine, also used by all iOS browsers)
- **watchOS/tvOS/visionOS** - Wearable and TV platforms

Apple vulnerabilities are high-value targets for nation-states and commercial spyware vendors.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `ht` | HT (Help Topic) Security Articles | HT214036 |

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
