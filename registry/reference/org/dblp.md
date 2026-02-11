---
namespace: dblp.org
full_name: "DBLP Computer Science Bibliography"
type: reference

urls:
  website: "https://dblp.org"
  lookup: "https://dblp.org/rec/{id}"
  api: "https://dblp.org/search/publ/api"

id_pattern: "[a-z]+/[a-zA-Z0-9/]+"
examples:
  - "conf/ccs/SmithJ23"
  - "journals/tissec/AndersonR01"
  - "conf/sp/DiffieH76"

status: draft
---

# DBLP Namespace

DBLP Computer Science Bibliography - comprehensive index of CS publications.

## Format

```
secid:reference/dblp.org/{key}
secid:reference/dblp.org/conf/ccs/SmithJ23
```

## Resolution

```
https://dblp.org/rec/{id}
```

## Key Structure

DBLP keys follow patterns:
- `conf/{venue}/{AuthorYY}` - Conference papers
- `journals/{journal}/{AuthorYY}` - Journal articles
- `books/{publisher}/{key}` - Books

## Security-Relevant Venues in DBLP

| Key Prefix | Venue |
|------------|-------|
| conf/ccs | ACM CCS |
| conf/sp | IEEE S&P |
| conf/uss | USENIX Security |
| conf/ndss | NDSS |
| conf/crypto | CRYPTO |
| conf/eurocrypt | EUROCRYPT |
| journals/tissec | ACM TOPS |

## Notes

- DBLP is a bibliography, not a full-text repository
- Links to publisher pages (IEEE, ACM, etc.)
- Excellent for finding papers and their metadata
- Free and open access to metadata
- Author pages aggregate all publications
