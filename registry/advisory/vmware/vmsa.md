---
type: advisory
namespace: vmware
name: vmsa
full_name: "VMware Security Advisory"
operator: "secid:entity/vmware"

urls:
  website: "https://www.vmware.com/security/advisories.html"
  lookup: "https://www.vmware.com/security/advisories/{id}.html"

id_pattern: "VMSA-\\d{4}-\\d{4}"

examples:
  - "secid:advisory/vmware/vmsa#VMSA-2024-0001"
  - "secid:advisory/vmware/vmsa#VMSA-2021-0028"

status: active
---

# VMware Security Advisory (VMSA)

VMware's official security advisories.

## Format

```
secid:advisory/vmware/vmsa#VMSA-YYYY-NNNN
```

## Resolution

```
secid:advisory/vmware/vmsa#VMSA-2021-0028
  → https://www.vmware.com/security/advisories/VMSA-2021-0028.html
```

## Notes

- VMSA advisories cover all VMware products (vSphere, ESXi, vCenter, etc.)
- Often bundle multiple CVEs per advisory
- VMware is now part of Broadcom (as of 2023)
