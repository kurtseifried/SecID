---
namespace: isbn.org
full_name: "International Standard Book Number"
type: reference

urls:
  website: "https://www.isbn-international.org"
  lookup: "https://www.worldcat.org/isbn/{id}"

id_pattern: "97[89]-?\\d{1,5}-?\\d{1,7}-?\\d{1,7}-?\\d"
examples:
  - "978-0-13-468599-1"
  - "9780134685991"

status: draft
---

# ISBN Namespace

International Standard Book Numbers - unique identifiers for books and book-like publications.

## Format

```
secid:reference/isbn.org/{isbn}
secid:reference/isbn.org/978-0-13-468599-1
```

## Resolution

WorldCat provides lookup by ISBN. Publisher and retailer sites also resolve ISBNs.

## Notes

- ISBN-13 format (starts with 978 or 979)
- Hyphens are optional but aid readability
- Different editions/formats of the same book have different ISBNs
- Many books also have DOIs, especially academic publications
- Equivalence between SecIDs belongs in the relationship layer
