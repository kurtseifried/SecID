---
type: advisory
namespace: cadmv
full_name: "California Department of Motor Vehicles"
operator: "secid:entity/california/dmv"
website: "https://www.dmv.ca.gov"
status: active

sources:
  av-collision:
    full_name: "Autonomous Vehicle Collision Reports"
    urls:
      website: "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/autonomous-vehicle-collision-reports/"
      data: "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/autonomous-vehicle-collision-reports/"
    examples:
      - "secid:advisory/cadmv/av-collision#report-id"

  av-disengagement:
    full_name: "Autonomous Vehicle Disengagement Reports"
    urls:
      website: "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/disengagement-reports/"
      data: "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/disengagement-reports/"
    examples:
      - "secid:advisory/cadmv/av-disengagement#report-id"

  av-permits:
    full_name: "Autonomous Vehicle Testing Permits"
    urls:
      website: "https://www.dmv.ca.gov/portal/vehicle-industry-services/autonomous-vehicles/"
    examples:
      - "secid:advisory/cadmv/av-permits"
---

# California DMV Autonomous Vehicle Reports

California requires autonomous vehicle manufacturers to report collisions and disengagements, creating the most detailed state-level AV incident database.

## Why California DMV Data Matters

Leading AV testing jurisdiction:

- **Most AV testing** - California hosts majority of US AV testing
- **Mandatory reporting** - Legal requirement for permit holders
- **Detailed data** - Collision and disengagement specifics
- **Historical record** - Data since 2014

---

## av-collision

Autonomous vehicle collision reports filed with California DMV.

### Format

```
secid:advisory/cadmv/av-collision#<report-id>
```

### Reporting Requirements

AV permit holders must report within 10 days:
- Any collision involving an AV in autonomous mode
- Any collision involving an AV in conventional mode
- Property damage, injury, or fatality

### Report Contents

| Field | Description |
|-------|-------------|
| Date/time | When collision occurred |
| Location | Street address, city |
| Weather | Conditions at time |
| Vehicle info | Make, model, VIN |
| AV mode | Autonomous or conventional |
| Damage | Property damage description |
| Injuries | Any injuries sustained |
| Other vehicles | Other parties involved |
| Description | Narrative of incident |

### Companies Reporting

Major AV developers testing in California:
- Waymo
- Cruise (GM)
- Zoox (Amazon)
- Nuro
- Apple
- Mercedes-Benz
- Many others

### Notes

- Public records
- Downloadable reports
- Used by researchers and media
- Complements federal NHTSA data

---

## av-disengagement

Annual disengagement reports from autonomous vehicle testing.

### Format

```
secid:advisory/cadmv/av-disengagement#<report-id>
```

### What's a Disengagement

When the AV's autonomous mode is deactivated:
- **By the system** - AV detects problem, hands control to human
- **By the driver** - Safety driver takes over

### Report Contents

| Field | Description |
|-------|-------------|
| Total miles | Autonomous miles driven |
| Disengagements | Number of disengagements |
| Rate | Disengagements per 1,000 miles |
| Causes | Categorized reasons |
| Locations | Where disengagements occurred |

### Disengagement Categories

| Category | Examples |
|----------|----------|
| Software | Perception failure, planning error |
| Hardware | Sensor malfunction |
| Weather | Rain, fog affecting sensors |
| Road conditions | Construction, unusual situation |
| Other road users | Unpredictable behavior |
| Precautionary | Driver takeover for safety |

### Annual Trends

| Year | Industry Trend |
|------|----------------|
| 2015-2018 | High disengagement rates |
| 2019-2021 | Improving, leaders under 0.1/1000 mi |
| 2022-2024 | Top performers very low rates |

### Limitations

- Self-reported data
- Inconsistent categorization between companies
- Some gaming of metrics
- Miles in easy vs hard conditions vary

### Notes

- Annual reports due by January 1
- Covers previous calendar year
- Public data
- Key metric for AV progress (with caveats)

---

## av-permits

Information on autonomous vehicle testing permits in California.

### Format

```
secid:advisory/cadmv/av-permits
```

### Permit Types

| Type | Requirements |
|------|--------------|
| **Testing with driver** | Safety driver present |
| **Driverless testing** | No safety driver required |
| **Deployment** | Commercial passenger service |

### Permit Holders

50+ companies hold AV testing permits, including:
- Major automakers
- Tech companies
- AV startups
- Trucking companies

### Notes

- Permit required for public road testing
- Different requirements for each permit type
- Permit holder list publicly available
