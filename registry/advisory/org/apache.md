---
type: advisory
namespace: apache.org
full_name: "Apache Software Foundation"
operator: "secid:entity/apache.org"
website: "https://www.apache.org"
status: active

sources:
  security:
    full_name: "Apache Security"
    urls:
      website: "https://www.apache.org/security/"
      project_security: "https://{project}.apache.org/security.html"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/apache.org/security#CVE-2021-44228"
      - "secid:advisory/apache.org/security#CVE-2024-1234"
  jira:
    full_name: "Apache Jira"
    urls:
      website: "https://issues.apache.org/jira"
      lookup: "https://issues.apache.org/jira/browse/{id}"
    id_pattern: "[A-Z]+-\\d+"
    examples:
      - "secid:advisory/apache.org/jira#LOG4J2-3201"
      - "secid:advisory/apache.org/jira#HTTPD-1234"
      - "secid:advisory/apache.org/jira#TOMCAT-5678"
---

# Apache Advisory Sources

The Apache Software Foundation (ASF) is a nonprofit organization that develops and maintains hundreds of open-source software projects. Apache projects include some of the most widely deployed server software.

## Why Apache Matters for Security

Apache projects run critical infrastructure worldwide:

- **Apache HTTP Server (httpd)** - One of the most popular web servers
- **Apache Tomcat** - Java servlet container
- **Apache Log4j** - Java logging library (Log4Shell)
- **Apache Kafka** - Distributed streaming platform
- **Apache Struts** - Web application framework (Equifax breach)

Apache vulnerabilities can have massive blast radius due to widespread deployment.

## Security Structure

Apache is an umbrella organization - each project maintains its own:
- Security page (e.g., logging.apache.org/log4j/2.x/security.html)
- Mailing list for security reports
- Release process for security fixes

There's no single "Apache advisory" - advisories come from individual projects.

## Notable Vulnerabilities

- **CVE-2021-44228 (Log4Shell)** - Critical Log4j RCE, one of the most impactful vulnerabilities ever
- **CVE-2017-5638** - Struts RCE that led to Equifax breach
- **CVE-2021-41773** - Apache HTTP Server path traversal

## Notes

- Apache is a CVE Numbering Authority (CNA) for its projects
- Security reports go to security@apache.org or project-specific lists
- Apache projects vary widely in security maturity

---

## security

Apache Software Foundation security information.

### Format

```
secid:advisory/apache.org/security#CVE-YYYY-NNNN
```

### Resolution

Apache projects maintain their own security pages. Resolution depends on the project:

```
secid:advisory/apache.org/security#CVE-2021-44228
  -> https://logging.apache.org/log4j/2.x/security.html (Log4j)

secid:advisory/apache.org/security#CVE-2024-1234
  -> https://httpd.apache.org/security/vulnerabilities_24.html (httpd)
```

### Notes

- Apache is an umbrella for many projects (httpd, Tomcat, Log4j, Struts, etc.)
- Each project maintains its own security page
- For project-specific bug tracking, see `secid:advisory/apache.org/jira`
- Consider using project-specific SecIDs when available

---

## jira

Apache Software Foundation's issue tracking system.

### Format

```
secid:advisory/apache.org/jira#PROJECT-NNNN
```

Project key (e.g., LOG4J2, HTTPD, TOMCAT) followed by issue number.

### Resolution

```
secid:advisory/apache.org/jira#LOG4J2-3201
  -> https://issues.apache.org/jira/browse/LOG4J2-3201
```

### Common Project Keys

| Key | Project |
|-----|---------|
| `LOG4J2` | Log4j 2.x |
| `HTTPD` | Apache HTTP Server |
| `TOMCAT` | Apache Tomcat |
| `STRUTS` | Apache Struts |
| `KAFKA` | Apache Kafka |
| `SPARK` | Apache Spark |

### Notes

- Security issues may be restricted until fixed
- The project key indicates which Apache project
- For official security pages, see `secid:advisory/apache.org/security`
