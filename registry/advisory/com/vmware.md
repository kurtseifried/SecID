---
type: advisory
namespace: vmware.com
full_name: "VMware (Broadcom)"
operator: "secid:entity/vmware.com"
website: "https://www.vmware.com"
status: active

sources:
  vmsa:
    full_name: "VMware Security Advisory"
    urls:
      website: "https://www.broadcom.com/support/vmware-security-advisories"
      lookup: "https://www.vmware.com/security/advisories/{id}.html"
      legacy: "https://www.vmware.com/security/advisories.html"
    id_pattern: "VMSA-\\d{4}-\\d{4}"
    examples:
      - "secid:advisory/vmware.com/vmsa#VMSA-2024-0001"
      - "secid:advisory/vmware.com/vmsa#VMSA-2021-0028"
---

# VMware Advisory Sources

VMware is the leading virtualization and cloud infrastructure company, producing vSphere, ESXi, vCenter, and related products. VMware was acquired by Broadcom in November 2023.

## Why VMware Matters for Security

VMware runs most enterprise virtualization:

- **ESXi** - Hypervisor running enterprise workloads
- **vCenter** - Management platform for VMware environments
- **vSphere** - Complete virtualization platform
- **NSX** - Network virtualization
- **Workspace ONE** - Endpoint management

Compromising VMware infrastructure can give attackers access to all hosted workloads. Ransomware groups frequently target ESXi.

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

---

## vmsa

VMware's official security advisories.

### Format

```
secid:advisory/vmware.com/vmsa#VMSA-YYYY-NNNN
```

### Resolution

```
secid:advisory/vmware.com/vmsa#VMSA-2021-0028
  -> https://www.vmware.com/security/advisories/VMSA-2021-0028.html
```

### Notes

- VMSA advisories cover all VMware products (vSphere, ESXi, vCenter, etc.)
- Often bundle multiple CVEs per advisory
- VMware was acquired by Broadcom (November 2023)
- Main advisory listing now at Broadcom site, individual VMSA URLs still work
