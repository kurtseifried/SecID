---
type: ttp
namespace: lockheedmartin.com
full_name: "Lockheed Martin"
operator: "secid:entity/lockheedmartin.com"
website: "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"
status: active

sources:
  killchain:
    full_name: "Cyber Kill Chain"
    urls:
      website: "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"
      paper: "https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf"
    versions:
      - "1.0"
    examples:
      - "secid:ttp/lockheedmartin.com/killchain#reconnaissance"
      - "secid:ttp/lockheedmartin.com/killchain#weaponization"
      - "secid:ttp/lockheedmartin.com/killchain#delivery"
      - "secid:ttp/lockheedmartin.com/killchain#exploitation"
      - "secid:ttp/lockheedmartin.com/killchain#installation"
      - "secid:ttp/lockheedmartin.com/killchain#c2"
      - "secid:ttp/lockheedmartin.com/killchain#actions-on-objectives"
---

# Lockheed Martin TTP Frameworks

Lockheed Martin developed the Cyber Kill Chain, one of the foundational models for understanding adversary operations. While MITRE ATT&CK provides detailed techniques, the Kill Chain provides the strategic phases.

## Why Lockheed Martin Matters

The Cyber Kill Chain changed how we think about attacks:

- **First systematic model** - Published 2011, foundational to threat modeling
- **Defense-focused** - Identifies where to break the chain
- **Industry standard** - Referenced in countless security frameworks
- **Strategic view** - Complements ATT&CK's tactical detail

---

## killchain

The Cyber Kill Chain describes the phases of a targeted cyber intrusion, from initial reconnaissance through achieving objectives.

### Format

```
secid:ttp/lockheedmartin.com/killchain#<phase>
```

### The Seven Phases

| Phase | Description | Defender Goal |
|-------|-------------|---------------|
| **reconnaissance** | Target research, harvesting emails, OSINT | Detect information gathering |
| **weaponization** | Coupling exploit with backdoor into payload | N/A (occurs off-network) |
| **delivery** | Transmitting weapon to target (email, web, USB) | Block delivery vectors |
| **exploitation** | Triggering the exploit (vulnerability, user action) | Patch, harden, train users |
| **installation** | Installing backdoor/implant on victim | Detect persistence mechanisms |
| **c2** | Command channel for remote control | Block/detect C2 traffic |
| **actions-on-objectives** | Achieving goals (exfil, destroy, encrypt) | Detect lateral movement, exfil |

### Phase Details

#### reconnaissance
```
secid:ttp/lockheedmartin.com/killchain#reconnaissance
```
Adversary gathers information about the target:
- Email addresses, org charts
- Technology stack identification
- Social media OSINT
- Network scanning

#### weaponization
```
secid:ttp/lockheedmartin.com/killchain#weaponization
```
Adversary creates attack payload:
- Exploit + backdoor combination
- Malicious documents
- Custom malware development

#### delivery
```
secid:ttp/lockheedmartin.com/killchain#delivery
```
Transmission to target environment:
- Phishing emails
- Watering hole websites
- USB drops
- Supply chain compromise

#### exploitation
```
secid:ttp/lockheedmartin.com/killchain#exploitation
```
Triggering the vulnerability:
- Software vulnerability exploitation
- User execution (macros, links)
- Zero-day exploitation

#### installation
```
secid:ttp/lockheedmartin.com/killchain#installation
```
Establishing persistence:
- Backdoor installation
- Registry modifications
- Scheduled tasks
- Service creation

#### c2
```
secid:ttp/lockheedmartin.com/killchain#c2
```
Command and control channel:
- HTTP/HTTPS beaconing
- DNS tunneling
- Custom protocols
- Cloud service abuse

#### actions-on-objectives
```
secid:ttp/lockheedmartin.com/killchain#actions-on-objectives
```
Mission completion:
- Data exfiltration
- Data destruction
- Ransomware deployment
- Lateral movement

### Mapping to ATT&CK

| Kill Chain Phase | ATT&CK Tactics |
|------------------|----------------|
| Reconnaissance | Reconnaissance (TA0043) |
| Weaponization | Resource Development (TA0042) |
| Delivery | Initial Access (TA0001) |
| Exploitation | Execution (TA0002) |
| Installation | Persistence (TA0003) |
| C2 | Command and Control (TA0011) |
| Actions on Objectives | Exfiltration (TA0010), Impact (TA0040) |

### Defensive Applications

The Kill Chain enables "defense in depth" - multiple opportunities to detect and disrupt:

| Phase | Detection/Prevention |
|-------|---------------------|
| Recon | Monitor for scanning, OSINT exposure |
| Delivery | Email filtering, web proxies, USB controls |
| Exploitation | Patching, exploit prevention, sandboxing |
| Installation | EDR, file integrity monitoring |
| C2 | Network monitoring, DNS analysis |
| Actions | DLP, segmentation, anomaly detection |

### Limitations

The Kill Chain has known limitations:
- **Linear assumption** - Real attacks may skip or repeat phases
- **External focus** - Less applicable to insider threats
- **Pre-ATT&CK** - Lacks technique-level detail

These limitations led to the Unified Kill Chain and ATT&CK's more detailed approach.

### Notes

- Published 2011 by Lockheed Martin
- Based on military kill chain concept
- Foundational to modern threat modeling
- Use alongside ATT&CK for complete picture
