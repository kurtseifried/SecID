---
type: advisory
namespace: apache
name: jira
full_name: "Apache Jira"
operator: "secid:entity/apache"

urls:
  website: "https://issues.apache.org/jira"
  lookup: "https://issues.apache.org/jira/browse/{id}"

id_pattern: "[A-Z]+-\\d+"

examples:
  - "secid:advisory/apache/jira#LOG4J2-3201"
  - "secid:advisory/apache/jira#HTTPD-1234"
  - "secid:advisory/apache/jira#TOMCAT-5678"

status: active
---

# Apache Jira

Apache Software Foundation's issue tracking system.

## Format

```
secid:advisory/apache/jira#PROJECT-NNNN
```

Project key (e.g., LOG4J2, HTTPD, TOMCAT) followed by issue number.

## Resolution

```
secid:advisory/apache/jira#LOG4J2-3201
  → https://issues.apache.org/jira/browse/LOG4J2-3201
```

## Common Project Keys

| Key | Project |
|-----|---------|
| `LOG4J2` | Log4j 2.x |
| `HTTPD` | Apache HTTP Server |
| `TOMCAT` | Apache Tomcat |
| `STRUTS` | Apache Struts |
| `KAFKA` | Apache Kafka |
| `SPARK` | Apache Spark |

## Notes

- Security issues may be restricted until fixed
- The project key indicates which Apache project
- For official security pages, see `secid:advisory/apache/security`
