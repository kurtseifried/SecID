---
namespace: vmware
full_name: "VMware (Broadcom)"
website: "https://www.vmware.com"
type: corporation
founded: 1998
headquarters: "Palo Alto, California, USA"
parent: "Broadcom Inc. (acquired November 2023)"
---

# VMware (Broadcom)

VMware is the leading virtualization and cloud infrastructure company, producing vSphere, ESXi, vCenter, and related products. VMware was acquired by Broadcom in November 2023.

## Why VMware Matters for Security

VMware runs most enterprise virtualization:

- **ESXi** - Hypervisor running enterprise workloads
- **vCenter** - Management platform for VMware environments
- **vSphere** - Complete virtualization platform
- **NSX** - Network virtualization
- **Workspace ONE** - Endpoint management

Compromising VMware infrastructure can give attackers access to all hosted workloads. Ransomware groups frequently target ESXi.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `vmsa` | VMware Security Advisories | VMSA-2021-0028 |

## Advisory ID Format

VMware uses VMSA-YYYY-NNNN format:
```
VMSA-2021-0028  (Log4Shell advisory)
VMSA-2024-0001  (first advisory of 2024)
```

## Broadcom Acquisition

VMware was acquired by Broadcom in November 2023. Security advisories are now also available through Broadcom's support portal, though individual VMSA URLs still work.

## Notes

- VMware vulnerabilities are high-priority targets for ransomware
- ESXi runs without traditional endpoint protection, making it attractive to attackers
- Many VMware vulnerabilities enable hypervisor escape or privilege escalation
