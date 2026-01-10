---

type: "entity"
namespace: "redhat"

common_name: "Red Hat"
full_name: "Red Hat, Inc."

urls:
  website: "https://www.redhat.com"
  security: "https://access.redhat.com/security/"

names:
  # OpenShift family - general entry plus specific product variants
  openshift:
    full_name: "Red Hat OpenShift"
    description: "Kubernetes-based container platform (general/umbrella term)"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift"
      docs: "https://docs.openshift.com"
      console: "https://console.redhat.com/openshift"
  openshift-container-platform:
    full_name: "Red Hat OpenShift Container Platform"
    description: "Self-managed OpenShift (the downloadable product)"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift/container-platform"
  rosa:
    full_name: "Red Hat OpenShift Service on AWS"
    description: "Managed OpenShift on AWS (jointly operated with AWS)"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift/aws"
      aws: "https://aws.amazon.com/rosa/"
  aro:
    full_name: "Azure Red Hat OpenShift"
    description: "Managed OpenShift on Azure (jointly operated with Microsoft)"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift/azure"
      azure: "https://azure.microsoft.com/en-us/products/openshift"
  openshift-dedicated:
    full_name: "Red Hat OpenShift Dedicated"
    description: "Managed OpenShift on AWS/GCP (operated by Red Hat)"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift/dedicated"
  rhel:
    full_name: "Red Hat Enterprise Linux"
    description: "Enterprise Linux distribution"
    urls:
      website: "https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux"
      docs: "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux"
  ansible:
    full_name: "Red Hat Ansible Automation Platform"
    description: "IT automation platform"
    urls:
      website: "https://www.redhat.com/en/technologies/management/ansible"
      docs: "https://docs.ansible.com"
      galaxy: "https://galaxy.ansible.com"
  satellite:
    full_name: "Red Hat Satellite"
    description: "Systems management platform"
    urls:
      website: "https://www.redhat.com/en/technologies/management/satellite"
  quay:
    full_name: "Red Hat Quay"
    description: "Container registry"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/quay"
      public: "https://quay.io"
  acs:
    full_name: "Red Hat Advanced Cluster Security"
    description: "Kubernetes-native security platform"
    urls:
      website: "https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes"

wikidata: "Q485809"
status: "active"
established: 1993
---


# Red Hat

Red Hat is an enterprise software company (now part of IBM) focused on open source solutions. They provide enterprise Linux, container platforms, and automation tools.

## Names in This Namespace

### OpenShift Family

| Name | Full Name | Description |
|------|-----------|-------------|
| `openshift` | Red Hat OpenShift | General/umbrella term |
| `openshift-container-platform` | OpenShift Container Platform | Self-managed product |
| `rosa` | ROSA | Managed on AWS (with AWS) |
| `aro` | ARO | Managed on Azure (with Microsoft) |
| `openshift-dedicated` | OpenShift Dedicated | Managed by Red Hat |

### Other Products

| Name | Full Name | Description |
|------|-----------|-------------|
| `rhel` | Red Hat Enterprise Linux | Enterprise Linux distribution |
| `ansible` | Red Hat Ansible Automation Platform | IT automation |
| `satellite` | Red Hat Satellite | Systems management |
| `quay` | Red Hat Quay | Container registry |
| `acs` | Red Hat Advanced Cluster Security | Kubernetes security |

## Examples

```
# General reference (most common use)
secid:entity/redhat/openshift   # OpenShift platform generally

# Specific variants (when distinction matters)
secid:entity/redhat/rosa        # ROSA - the managed AWS service
secid:entity/redhat/aro         # ARO - the managed Azure service

# Other products
secid:entity/redhat/rhel        # RHEL operating system
secid:entity/redhat/ansible     # Ansible automation
```

## Naming Convention

Names follow what Red Hat officially calls them:
- `rosa` not `openshift-rosa` (Red Hat calls it "ROSA")
- `aro` not `openshift-aro` (it's "Azure Red Hat OpenShift" → ARO)
- `openshift-dedicated` uses the full name (no common acronym)

Use `openshift` for general references. Use specific names when security context requires distinguishing (e.g., "this CVE affects only self-managed OpenShift, not ROSA").

## Security Content

Red Hat operates a comprehensive security response program:

- **Security advisories**: RHSA, RHBA, RHEA (see `advisory/redhat`)
- **CVE database**: Red Hat's CVE pages with their own analysis
- **Bugzilla**: Bug tracking including security issues

## Notes

- Red Hat was acquired by IBM in 2019
- OpenShift is both a product and a managed service
- Many Red Hat products are based on upstream open source projects
