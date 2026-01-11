# Cyber Threat Intelligence Type (`cti`)

> **STATUS: DEFERRED** - This type is not yet implemented. The design below is exploratory and will be revised when we return to CTI.

## Design Notes for Future Implementation

When CTI is implemented, namespaces should represent **CTI databases/sources**, not object types:

```
secid:cti/misp/...           # MISP threat intel
secid:cti/opencti/...        # OpenCTI platform
secid:cti/alienvault/...     # AlienVault OTX
secid:cti/mandiant/...       # Mandiant threat intel
secid:cti/recordedfuture/... # Recorded Future
secid:cti/crowdstrike/...    # CrowdStrike intel
```

This follows the same pattern as advisory (cve, nvd, ghsa, redhat) where the namespace is the source/authority.

See [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) for potential namespaces.

The object type (actor, campaign, malware, indicator) would be part of the name or handled via the source's native identifiers.

---

## Original Draft (Needs Revision)

This type contains references to observed adversary activity - incidents, campaigns, and threat actors.

## Purpose

Track and reference threat intelligence artifacts - the "what happened" and "who did it":
- Incidents (specific security events)
- Campaigns (coordinated adversary operations)
- Threat actors (adversary groups and individuals)
- Malware (malicious software families)

## Identifier Format

```
secid:cti/<namespace>/<type>/<id>

secid:cti/campaign/apt29-solarwinds
secid:cti/actor/apt29
secid:cti/incident/2024-crowdstrike-outage
secid:cti/malware/emotet
```

For STIX-formatted intelligence:

```
secid:cti/stix/threat-actor--xxx
secid:cti/stix/campaign--xxx
secid:cti/stix/indicator--xxx
```

## Namespaces

| Namespace | Source | Description |
|-----------|--------|-------------|
| `campaign` | Various | Named adversary campaigns |
| `actor` | Various | Threat actor groups |
| `incident` | Various | Security incidents |
| `malware` | Various | Malware families |
| `stix` | OASIS STIX | STIX-formatted objects |

## CTI Object Types

Common CTI object types (aligned with STIX 2.1):

| Type | Description | Example |
|------|-------------|---------|
| `campaign` | Coordinated adversary activity | SolarWinds supply chain attack |
| `actor` | Threat actor or group | APT29, Lazarus Group |
| `incident` | Specific security event | 2024 CrowdStrike outage |
| `malware` | Malicious software family | Emotet, TrickBot |
| `intrusion-set` | Related intrusion activity | |

## Relationships

CTI connects to TTPs (how they attack):

```json
{
  "from": "secid:cti/actor/apt29",
  "to": "secid:ttp/mitre/attack#T1566.001",
  "type": "uses",
  "description": "APT29 uses spearphishing attachments"
}
```

CTI connects to advisories (what they exploit):

```json
{
  "from": "secid:cti/campaign/apt29-solarwinds",
  "to": "secid:advisory/mitre/cve#CVE-2020-10148",
  "type": "exploits",
  "description": "Campaign exploited SolarWinds Orion vulnerability"
}
```

CTI connects to malware:

```json
{
  "from": "secid:cti/actor/apt29",
  "to": "secid:cti/malware/sunburst",
  "type": "uses",
  "description": "APT29 deployed SUNBURST malware"
}
```

## STIX Integration

STIX (Structured Threat Information Expression) is the standard format for CTI. Many sources publish STIX-formatted data:
- ATT&CK publishes techniques in STIX
- ATLAS publishes AI attack techniques in STIX
- Threat intel feeds use STIX for sharing

```json
{
  "from": "secid:cti/stix/attack-pattern--xxx",
  "to": "secid:ttp/mitre/attack#T1566",
  "type": "represents",
  "description": "STIX object representing ATT&CK technique"
}
```

## CTI vs TTP vs Advisory

- **CTI** (cti): Observed adversary activity (who did what, when)
- **TTP** (ttp): Abstract attack techniques (how attacks work)
- **Advisory** (advisory): Vulnerability publications (what's vulnerable)

CTI is about **observed reality**. TTPs are **attack patterns**. Advisories are **vulnerability records**.

## Notes

- STIX is the format, TAXII is the transport protocol
- Most threat intel feeds use STIX 2.x format
- ATT&CK groups (G0016) and software (S0154) are also CTI-adjacent

