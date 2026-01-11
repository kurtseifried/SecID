---
type: advisory
namespace: apache
name: security
full_name: "Apache Security"
operator: "secid:entity/apache"

urls:
  website: "https://www.apache.org/security/"
  project_security: "https://{project}.apache.org/security.html"

id_patterns:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE identifier"
    type: primary

examples:
  - "secid:advisory/apache/security#CVE-2021-44228"
  - "secid:advisory/apache/security#CVE-2024-1234"

status: active
---

# Apache Security

Apache Software Foundation security information.

## Format

```
secid:advisory/apache/security#CVE-YYYY-NNNN
```

## Resolution

Apache projects maintain their own security pages. Resolution depends on the project:

```
secid:advisory/apache/security#CVE-2021-44228
  → https://logging.apache.org/log4j/2.x/security.html (Log4j)

secid:advisory/apache/security#CVE-2024-1234
  → https://httpd.apache.org/security/vulnerabilities_24.html (httpd)
```

## Notes

- Apache is an umbrella for many projects (httpd, Tomcat, Log4j, Struts, etc.)
- Each project maintains its own security page
- For project-specific bug tracking, see `secid:advisory/apache/jira`
- Consider using project-specific SecIDs when available
