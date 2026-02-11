---
namespace: amazon.com
full_name: "Amazon Standard Identification Number"
type: reference

urls:
  website: "https://www.amazon.com"
  lookup: "https://www.amazon.com/dp/{id}"

id_pattern: "[A-Z0-9]{10}"
examples:
  - "B0C5PBBKNZ"
  - "0596007124"

status: draft
---

# ASIN Namespace

Amazon Standard Identification Numbers - unique identifiers for products on Amazon, including books and digital content.

## Format

```
secid:reference/amazon.com/{asin}
secid:reference/amazon.com/B0C5PBBKNZ
```

## Resolution

```
https://www.amazon.com/dp/{id}
```

## Notes

- 10-character alphanumeric identifier
- For books, ASIN often equals ISBN-10 (older format)
- Kindle editions and other Amazon-only products have unique ASINs
- Amazon-specific; may not be stable long-term
- Equivalence between ASIN and ISBN belongs in the relationship layer
