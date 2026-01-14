---
namespace: apache
full_name: "Apache Software Foundation"
website: "https://www.apache.org"
type: nonprofit
founded: 1999
headquarters: "Wilmington, Delaware, USA (incorporated)"
---

# Apache Software Foundation

The Apache Software Foundation (ASF) is a nonprofit organization that develops and maintains hundreds of open-source software projects. Apache projects include some of the most widely deployed server software.

## Why Apache Matters for Security

Apache projects run critical infrastructure worldwide:

- **Apache HTTP Server (httpd)** - One of the most popular web servers
- **Apache Tomcat** - Java servlet container
- **Apache Log4j** - Java logging library (Log4Shell)
- **Apache Kafka** - Distributed streaming platform
- **Apache Struts** - Web application framework (Equifax breach)

Apache vulnerabilities can have massive blast radius due to widespread deployment.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `security` | Per-project security pages | CVE-2021-44228 |
| `jira` | Apache Jira issue tracker | LOG4J2-3201 |

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
