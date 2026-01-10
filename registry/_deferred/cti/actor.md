---
namespace: actor
full_name: "Threat Actors"
type: cti
subtype: actor

urls:
  mitre: "https://attack.mitre.org/groups/"
  malpedia: "https://malpedia.caad.fkie.fraunhofer.de/actors"

examples:
  - "apt29"
  - "apt28"
  - "lazarus"
  - "fin7"

status: active
---

# Threat Actor Namespace

Named threat actors and groups.

## Format

```
secid:cti/actor/{name}
secid:cti/actor/apt29
```

## Naming Conventions

Use lowercase, hyphenated canonical names:
- `apt29` (not APT29, Cozy Bear, etc.)
- `lazarus` (not Lazarus Group)
- `fin7` (not FIN7)

## Well-Known Actors

| ID | Aliases | Attribution |
|----|---------|-------------|
| apt29 | Cozy Bear, The Dukes | Russia/SVR |
| apt28 | Fancy Bear, Sofacy | Russia/GRU |
| lazarus | Hidden Cobra | North Korea |
| apt41 | Winnti, Barium | China |
| fin7 | Carbanak | Cybercrime |

## Relationships

```
cti/actor/apt29 → uses → ttp/attack/T1566
cti/actor/apt29 → attributed_to → cti/campaign/solarwinds-2020
```

## Notes

- Aliases stored in metadata, not ID
- Attribution is contentious - use relationships
- Maps to MITRE ATT&CK Groups
