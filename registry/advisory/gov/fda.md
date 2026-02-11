---
type: advisory
namespace: fda.gov
full_name: "U.S. Food and Drug Administration"
operator: "secid:entity/usgov/hhs/fda"
website: "https://www.fda.gov"
status: active

sources:
  maude:
    full_name: "MAUDE Medical Device Adverse Events"
    urls:
      website: "https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfmaude/search.cfm"
      data: "https://www.fda.gov/medical-devices/mandatory-reporting-requirements-manufacturers-importers-and-device-user-facilities/about-maude"
    examples:
      - "secid:advisory/fda.gov/maude#report-number"

  aiml-devices:
    full_name: "AI/ML-Enabled Medical Devices"
    urls:
      website: "https://www.fda.gov/medical-devices/software-medical-device-samd/artificial-intelligence-and-machine-learning-aiml-enabled-medical-devices"
      list: "https://www.fda.gov/medical-devices/software-medical-device-samd/artificial-intelligence-and-machine-learning-aiml-enabled-medical-devices#702devices"
    examples:
      - "secid:advisory/fda.gov/aiml-devices#device-name"

  recalls:
    full_name: "Medical Device Recalls"
    urls:
      website: "https://www.fda.gov/medical-devices/medical-device-recalls"
      search: "https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfRES/res.cfm"
    examples:
      - "secid:advisory/fda.gov/recalls#recall-number"
---

# FDA AI/ML Medical Device Safety

FDA regulates AI/ML-enabled medical devices and tracks adverse events and recalls.

## Why FDA Data Matters

Critical for healthcare AI safety:

- **900+ devices** - Authorized AI/ML medical devices
- **Adverse events** - MAUDE database tracks incidents
- **Regulatory precedent** - First major AI/ML device approvals
- **Growing field** - Rapid increase in AI/ML submissions

---

## maude

MAUDE (Manufacturer and User Facility Device Experience) database tracks medical device adverse events, including AI/ML devices.

### Format

```
secid:advisory/fda.gov/maude#<report-number>
```

### Report Types

| Type | Source |
|------|--------|
| **Manufacturer reports** | Required adverse event reports |
| **User facility reports** | Hospital/clinic reports |
| **Voluntary reports** | Healthcare provider submissions |
| **Distributor reports** | Supply chain reports |

### AI/ML Device Categories

Filter MAUDE for AI/ML devices in:
- Radiology (imaging AI)
- Cardiology (ECG analysis)
- Ophthalmology (retinal screening)
- Pathology (tissue analysis)
- Clinical decision support

### Search Strategies

To find AI/ML-related reports:
- Search by device brand names
- Filter by product codes
- Search narrative text for "AI", "algorithm", "machine learning"

### Notable Incident Types

| Category | Examples |
|----------|----------|
| False negatives | Missed diagnoses |
| False positives | Incorrect alerts |
| Software failures | System crashes, errors |
| Integration issues | EHR/workflow problems |

### Notes

- Reports since 1991
- Millions of records total
- AI/ML subset growing rapidly
- Used for post-market surveillance

---

## aiml-devices

FDA maintains a list of authorized AI/ML-enabled medical devices.

### Format

```
secid:advisory/fda.gov/aiml-devices#<device-identifier>
```

### Device Count by Year

| Year | New Authorizations |
|------|-------------------|
| 2020 | ~100 |
| 2021 | ~150 |
| 2022 | ~200 |
| 2023 | ~250 |
| 2024 | ~200+ |
| **Total** | **900+** |

### Categories by Specialty

| Specialty | Device Count |
|-----------|--------------|
| Radiology | ~400 |
| Cardiology | ~150 |
| Neurology | ~50 |
| Ophthalmology | ~50 |
| Other | ~250 |

### Authorization Pathways

| Pathway | Description |
|---------|-------------|
| **510(k)** | Substantial equivalence to predicate |
| **De Novo** | Novel low-to-moderate risk |
| **PMA** | High-risk premarket approval |

### Notable Devices

| Device | Function | Year |
|--------|----------|------|
| IDx-DR | Autonomous diabetic retinopathy | 2018 |
| Caption AI | Echocardiogram guidance | 2020 |
| Paige Prostate | Cancer detection in pathology | 2021 |

### Notes

- List updated periodically
- First autonomous diagnostic 2018
- Rapid growth in submissions
- International harmonization ongoing

---

## recalls

Medical device recalls include AI/ML-enabled devices with safety issues.

### Format

```
secid:advisory/fda.gov/recalls#<recall-number>
```

### Recall Classifications

| Class | Severity |
|-------|----------|
| **Class I** | Serious adverse health consequences or death |
| **Class II** | Temporary or reversible health problems |
| **Class III** | Unlikely to cause adverse health consequences |

### AI/ML Recall Categories

| Category | Examples |
|----------|----------|
| **Algorithm errors** | Incorrect calculations, predictions |
| **Software bugs** | Crashes, data corruption |
| **Cybersecurity** | Vulnerabilities, unauthorized access |
| **Labeling** | Incorrect instructions for use |

### Search Parameters

Find AI/ML recalls by:
- Device name
- Manufacturer
- Recall classification
- Date range

### Notes

- Part of broader medical device recall database
- Includes software-as-medical-device recalls
- Growing category as AI/ML devices increase
- Linked to MAUDE adverse event reports
