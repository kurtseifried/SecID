---
type: ttp
namespace: unifiedkillchain.com
full_name: "Unified Kill Chain"
operator: "secid:entity/unifiedkillchain.com"
website: "https://www.unifiedkillchain.com"
status: active

sources:
  ukc:
    full_name: "Unified Kill Chain"
    urls:
      website: "https://www.unifiedkillchain.com"
      pdf: "https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf"
    versions:
      - "2.2"
    examples:
      - "secid:ttp/unifiedkillchain.com/ukc#initial-foothold"
      - "secid:ttp/unifiedkillchain.com/ukc#network-propagation"
      - "secid:ttp/unifiedkillchain.com/ukc#action-on-objectives"
---

# Unified Kill Chain

The Unified Kill Chain (UKC) extends and modernizes the Lockheed Martin Cyber Kill Chain by incorporating MITRE ATT&CK tactics and addressing the original model's limitations.

## Why Unified Kill Chain Matters

UKC bridges strategic and tactical views:

- **Combines frameworks** - Merges Kill Chain phases with ATT&CK tactics
- **Addresses limitations** - Handles non-linear attacks, insider threats
- **Modern attacks** - Covers ransomware, supply chain, cloud
- **Practical** - Used for threat modeling and red teaming

## Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| Lockheed Kill Chain | UKC extends and modernizes it |
| MITRE ATT&CK | UKC incorporates ATT&CK tactics |
| Diamond Model | Complementary adversary analysis |

---

## ukc

The Unified Kill Chain describes attack progression through three major phases, each containing multiple tactics.

### Format

```
secid:ttp/unifiedkillchain.com/ukc#<phase>
secid:ttp/unifiedkillchain.com/ukc#<tactic>
```

### Three Major Phases

| Phase | Description | Contains |
|-------|-------------|----------|
| **Initial Foothold** | Getting into the network | Recon through persistence |
| **Network Propagation** | Moving through the network | Discovery through lateral movement |
| **Action on Objectives** | Achieving goals | Collection through impact |

### Phase 1: Initial Foothold

```
secid:ttp/unifiedkillchain.com/ukc#initial-foothold
```

Gaining and maintaining initial access:

| Tactic | Description |
|--------|-------------|
| Reconnaissance | Information gathering about target |
| Weaponization | Creating malicious payloads |
| Delivery | Transmitting payload to target |
| Social Engineering | Manipulating users |
| Exploitation | Triggering vulnerabilities |
| Persistence | Maintaining access |
| Defense Evasion | Avoiding detection |
| Command & Control | Establishing communication |

### Phase 2: Network Propagation

```
secid:ttp/unifiedkillchain.com/ukc#network-propagation
```

Moving through the environment:

| Tactic | Description |
|--------|-------------|
| Discovery | Learning about the environment |
| Privilege Escalation | Gaining higher permissions |
| Execution | Running attacker code |
| Credential Access | Stealing credentials |
| Lateral Movement | Moving to other systems |

### Phase 3: Action on Objectives

```
secid:ttp/unifiedkillchain.com/ukc#action-on-objectives
```

Completing the mission:

| Tactic | Description |
|--------|-------------|
| Collection | Gathering target data |
| Exfiltration | Stealing data |
| Impact | Disruption, destruction, manipulation |
| Objectives | Mission-specific goals |

### Full 18 Tactics

| # | Tactic | Phase |
|---|--------|-------|
| 1 | Reconnaissance | Initial Foothold |
| 2 | Weaponization | Initial Foothold |
| 3 | Delivery | Initial Foothold |
| 4 | Social Engineering | Initial Foothold |
| 5 | Exploitation | Initial Foothold |
| 6 | Persistence | Initial Foothold |
| 7 | Defense Evasion | Initial Foothold |
| 8 | Command & Control | Initial Foothold |
| 9 | Pivoting | Network Propagation |
| 10 | Discovery | Network Propagation |
| 11 | Privilege Escalation | Network Propagation |
| 12 | Execution | Network Propagation |
| 13 | Credential Access | Network Propagation |
| 14 | Lateral Movement | Network Propagation |
| 15 | Collection | Action on Objectives |
| 16 | Exfiltration | Action on Objectives |
| 17 | Impact | Action on Objectives |
| 18 | Objectives | Action on Objectives |

### Key Improvements Over Kill Chain

| Limitation | UKC Solution |
|------------|--------------|
| Linear assumption | Cyclic model, tactics can repeat |
| External focus only | Includes insider threat paths |
| No ATT&CK mapping | Built on ATT&CK tactics |
| Missing tactics | Adds pivoting, social engineering |

### Attack Scenarios

UKC models various attack types:

| Attack Type | Key Phases |
|-------------|------------|
| Ransomware | Full chain → Impact (encryption) |
| Data theft | Full chain → Exfiltration |
| Insider threat | Starts at Network Propagation |
| Supply chain | Starts before Initial Foothold |

### Threat Modeling Use

UKC is useful for:
1. **Red team planning** - Structure attack simulations
2. **Detection engineering** - Identify coverage gaps
3. **Incident analysis** - Classify attacker progress
4. **Risk assessment** - Understand attack paths

### Notes

- Developed by Paul Pols (2017, updated 2022)
- Version 2.2 is current
- Freely available at unifiedkillchain.com
- Complements ATT&CK's technique-level detail
