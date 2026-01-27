---
type: advisory
namespace: nhtsa
full_name: "National Highway Traffic Safety Administration"
operator: "secid:entity/usgov/dot/nhtsa"
website: "https://www.nhtsa.gov"
status: active

sources:
  sgo:
    full_name: "Standing General Order Crash Reports"
    urls:
      website: "https://www.nhtsa.gov/laws-regulations/standing-general-order-crash-reporting"
      data: "https://www.nhtsa.gov/laws-regulations/standing-general-order-crash-reporting#data"
    examples:
      - "secid:advisory/nhtsa/sgo#incident-id"

  av-recalls:
    full_name: "Autonomous Vehicle Recalls"
    urls:
      website: "https://www.nhtsa.gov/recalls-spotlight/automated-vehicle-recalls"
      search: "https://www.nhtsa.gov/recalls"
    examples:
      - "secid:advisory/nhtsa/av-recalls#recall-number"

  odi:
    full_name: "Office of Defects Investigation"
    urls:
      website: "https://www.nhtsa.gov/vehicle-safety/vehicle-related-complaints"
      complaints: "https://www.nhtsa.gov/vehicle/search-vehicle-complaint"
    examples:
      - "secid:advisory/nhtsa/odi#complaint-id"
---

# NHTSA Autonomous Vehicle Safety Data

NHTSA collects mandatory incident reports for vehicles with advanced driver assistance systems (ADAS) and autonomous driving systems.

## Why NHTSA Data Matters

Primary source for AV safety incidents:

- **Mandatory reporting** - Manufacturers must report crashes
- **Comprehensive** - 700+ incidents reported since 2021
- **Official** - Government regulatory data
- **Actionable** - Leads to recalls and investigations

---

## sgo

Standing General Order (SGO) crash reporting requires manufacturers to report incidents involving ADAS and ADS equipped vehicles.

### Format

```
secid:advisory/nhtsa/sgo#<incident-id>
```

### Reporting Requirements

| Criterion | Threshold |
|-----------|-----------|
| **ADS vehicles** | Any crash |
| **ADAS vehicles** | Crashes with fatality, injury, or property damage |
| **Timeframe** | Within 1 day (fatal) or 10 days (other) |

### Data Fields

| Field | Description |
|-------|-------------|
| Make/Model | Vehicle identification |
| Incident date | When crash occurred |
| Location | State and road type |
| Injuries | Severity classification |
| ADAS/ADS status | Whether system was engaged |

### Coverage Statistics

| Metric | Count |
|--------|-------|
| Reports since 2021 | 700+ |
| Manufacturers reporting | 100+ |
| Fatal incidents | Tracked separately |

### Notable Patterns

Data reveals patterns in:
- Rear-end collisions during ADAS use
- Low-speed autonomy incidents
- Pedestrian and cyclist incidents
- Emergency vehicle interactions

### Notes

- Reporting began July 2021
- Data released quarterly
- Includes Tesla, GM, Ford, Waymo, etc.
- Subject of ongoing analysis

---

## av-recalls

NHTSA tracks safety recalls for vehicles with autonomous and driver assistance features.

### Format

```
secid:advisory/nhtsa/av-recalls#<recall-number>
```

### Recall Categories

| Category | Examples |
|----------|----------|
| **ADS recalls** | Full self-driving system defects |
| **ADAS recalls** | Lane keeping, collision avoidance issues |
| **Software recalls** | OTA updates for safety issues |

### Notable Recalls

| Manufacturer | Issue | Vehicles |
|--------------|-------|----------|
| Tesla | Autopilot behavior | Millions |
| GM/Cruise | ADS stopping issues | Thousands |
| Various | Forward collision warning failures | Various |

### Resolution

Search NHTSA recall database at `https://www.nhtsa.gov/recalls` by:
- Manufacturer
- Year
- Recall number
- VIN

### Notes

- Software recalls increasingly common
- OTA updates enable faster remediation
- Tied to ODI investigations
- Public recall announcements

---

## odi

The Office of Defects Investigation handles consumer complaints and safety investigations.

### Format

```
secid:advisory/nhtsa/odi#<complaint-id>
```

### Complaint Types

| Type | Description |
|------|-------------|
| **Owner complaints** | Consumer-reported issues |
| **Manufacturer reports** | Required defect notifications |
| **Investigation requests** | Petitions for investigation |

### ADAS/ADS Relevance

Complaints tracked for:
- Autopilot and FSD behavior
- Emergency braking failures
- Lane departure warnings
- Parking assist issues
- Phantom braking

### Investigation Phases

| Phase | Description |
|-------|-------------|
| Screening | Initial review |
| Preliminary Evaluation | Data gathering |
| Engineering Analysis | Detailed investigation |
| Recall Request | If defect confirmed |

### Notes

- Public complaint database
- Searchable by vehicle/issue
- Informs recall decisions
- Used by researchers and media
