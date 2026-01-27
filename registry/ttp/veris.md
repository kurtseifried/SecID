---
type: ttp
namespace: veris
full_name: "VERIS Framework"
operator: "secid:entity/verizon"
website: "http://veriscommunity.net"
status: active

sources:
  framework:
    full_name: "Vocabulary for Event Recording and Incident Sharing"
    urls:
      website: "http://veriscommunity.net"
      github: "https://github.com/vz-risk/veris"
      schema: "https://github.com/vz-risk/veris/tree/master/verisc-labels"
      dbir: "https://www.verizon.com/business/resources/reports/dbir/"
    versions:
      - "1.3.7"
    examples:
      - "secid:ttp/veris/framework#action.hacking"
      - "secid:ttp/veris/framework#action.malware"
      - "secid:ttp/veris/framework#action.social"
      - "secid:ttp/veris/framework#actor.external"
---

# VERIS Framework

VERIS (Vocabulary for Event Recording and Incident Sharing) is a structured framework for describing security incidents. It's the classification system behind Verizon's Data Breach Investigations Report (DBIR).

## Why VERIS Matters

VERIS enables data-driven security:

- **Powers the DBIR** - Industry's most-cited breach report
- **Structured vocabulary** - Consistent incident classification
- **Community-driven** - Open framework, shared data
- **Statistical analysis** - Enables breach trend analysis

## The A4 Model

VERIS uses the "A4" model to describe incidents:
- **Actor** - Who did it
- **Action** - What they did
- **Asset** - What was affected
- **Attribute** - How it was affected (CIA)

---

## framework

VERIS provides a comprehensive vocabulary for classifying security incidents across multiple dimensions.

### Format

```
secid:ttp/veris/framework#<category>.<subcategory>
```

### The A4 Grid

| Dimension | Question | Categories |
|-----------|----------|------------|
| **Actor** | Who? | External, Internal, Partner |
| **Action** | What? | Hacking, Malware, Social, Misuse, Physical, Error, Environmental |
| **Asset** | Which? | Server, Network, User Device, Media, Person, Kiosk |
| **Attribute** | How? | Confidentiality, Integrity, Availability |

### Actor Categories

```
secid:ttp/veris/framework#actor.external
secid:ttp/veris/framework#actor.internal
secid:ttp/veris/framework#actor.partner
```

| Actor | Description | Examples |
|-------|-------------|----------|
| **External** | Outside the organization | Criminals, nation-states, hacktivists |
| **Internal** | Employees, contractors | Malicious insiders, negligent users |
| **Partner** | Third parties with access | Vendors, suppliers, service providers |

### Action Categories (TTPs)

```
secid:ttp/veris/framework#action.hacking
secid:ttp/veris/framework#action.malware
secid:ttp/veris/framework#action.social
secid:ttp/veris/framework#action.misuse
secid:ttp/veris/framework#action.physical
secid:ttp/veris/framework#action.error
secid:ttp/veris/framework#action.environmental
```

| Action | Description | Examples |
|--------|-------------|----------|
| **Hacking** | Unauthorized access attempts | Exploitation, brute force, SQLi |
| **Malware** | Malicious software | Ransomware, backdoors, keyloggers |
| **Social** | Social engineering | Phishing, pretexting, bribery |
| **Misuse** | Privilege abuse | Data theft by insiders, policy violations |
| **Physical** | Physical actions | Theft, tampering, snooping |
| **Error** | Mistakes | Misdelivery, misconfiguration, disposal errors |
| **Environmental** | Natural events | Power outage, fire, flood |

### Action Varieties (Sub-categories)

Each action has specific varieties:

**Hacking varieties:**
- Use of stolen creds
- Exploitation of vulnerabilities
- Brute force
- SQL injection
- Path traversal

**Malware varieties:**
- Ransomware
- Backdoor
- C2
- Downloader
- Keylogger/Spyware
- RAM scraper

**Social varieties:**
- Phishing
- Pretexting
- Bribery
- Extortion
- Influence campaigns

### Asset Categories

```
secid:ttp/veris/framework#asset.server
secid:ttp/veris/framework#asset.network
secid:ttp/veris/framework#asset.user-device
```

| Asset | Examples |
|-------|----------|
| Server | Web, database, file, mail servers |
| Network | Router, firewall, switch |
| User Device | Desktop, laptop, mobile |
| Media | Documents, payment cards, flash drives |
| Person | Employees, customers |

### Attribute (Impact)

```
secid:ttp/veris/framework#attribute.confidentiality
secid:ttp/veris/framework#attribute.integrity
secid:ttp/veris/framework#attribute.availability
```

| Attribute | Impact Type |
|-----------|-------------|
| Confidentiality | Data disclosure, exposure |
| Integrity | Data modification, fraud |
| Availability | System downtime, destruction |

### DBIR Statistics

VERIS enables DBIR findings like:
- "74% of breaches involved the human element"
- "Ransomware involved in 24% of breaches"
- "Stolen credentials used in 49% of breaches"

### Mapping to ATT&CK

| VERIS Action | ATT&CK Tactics |
|--------------|----------------|
| Hacking | Initial Access, Execution, Lateral Movement |
| Malware | Execution, Persistence, C2 |
| Social | Initial Access (Phishing) |
| Misuse | Collection, Exfiltration |

### Using VERIS

VERIS is useful for:
1. **Incident classification** - Consistent categorization
2. **Metrics and reporting** - Enable trend analysis
3. **Threat modeling** - Understand likely scenarios
4. **Benchmarking** - Compare to DBIR statistics

### Community Resources

- **VCDB** - VERIS Community Database (public incidents)
- **veris2stix** - Convert VERIS to STIX format
- **verispy** - Python library for VERIS

### Notes

- Developed by Verizon RISK Team
- Powers the annual DBIR report
- Open source at github.com/vz-risk/veris
- JSON schema for structured data
- Version 1.3.7 is current
