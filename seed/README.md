# Seed Data

This directory contains CSV files with research data for populating the SecID registry.

## Purpose

These files are **research inputs**, not authoritative data:
- Collected from various sources during initial research
- Used to identify namespaces and sources to add to the registry
- May be incomplete, outdated, or contain errors

**The registry (`registry/`) is the authoritative source.** These CSVs are reference material.

## Files

| File | Contents |
|------|----------|
| `seed-controls.csv` | Security control frameworks (CCM, NIST CSF, ISO, etc.) |
| `seed-regulations.csv` | Laws and regulations (GDPR, HIPAA, etc.) |
| `seed-vulndbs.csv` | Vulnerability databases and advisories |
| `seed-ai-weaknesses.csv` | AI/ML weakness taxonomies |
| `seed-standards.csv` | Security standards |
| `seed-certifications.csv` | Security certifications |
| `seed-list.csv` | General reference list |
| `seed-references.csv` | Reference documents |
| `seed-research.csv` | Research papers and resources |
| `seed-relationships.csv` | Relationship mapping research |
| `seed-cloud-providers.csv` | Cloud provider information |
| `seed-container-security.csv` | Container security tools/frameworks |
| `seed-scanners.csv` | Security scanners |
| `seed-threatintel.csv` | Threat intelligence sources |
| `seed-malware-analysis.csv` | Malware analysis resources |
| `seed-exploits.csv` | Exploit databases |
| `seed-bugbounty.csv` | Bug bounty platforms |
| `seed-supplychain.csv` | Supply chain security |
| `seed-certs.csv` | Certificate/credential information |

## Workflow

1. **Research phase**: Add data to relevant CSV file
2. **Registry creation**: Use CSV as reference to create proper registry entry in `registry/`
3. **Validation**: Registry entry becomes authoritative; CSV is historical reference

## CSV Format

Most files follow a similar structure:
```csv
short_name,full_name,maintainer,domain,url,current_version,notes
```

Columns vary by file type. Check the header row of each file.

## Contributing

- Add new research data to appropriate CSV
- Do NOT treat CSVs as source of truth for the registry
- Create proper registry entries in `registry/` based on research
