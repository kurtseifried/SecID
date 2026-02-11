---
namespace: semanticscholar.org
full_name: "Semantic Scholar"
type: reference

urls:
  website: "https://www.semanticscholar.org"
  lookup: "https://www.semanticscholar.org/paper/{id}"
  api: "https://api.semanticscholar.org/graph/v1/paper/{id}"

id_pattern: "[a-f0-9]{40}"
examples:
  - "649def34f8be52c8b66281af98ae884c09aef38b"
  - "204e3073870fae3d05bcbc2f6a8e263d9b72e776"

status: draft
---

# Semantic Scholar Namespace

Semantic Scholar - AI-powered research discovery platform with ~200 million papers.

## Format

```
secid:reference/semanticscholar.org/{paper-id}
secid:reference/semanticscholar.org/649def34f8be52c8b66281af98ae884c09aef38b
```

## Resolution

```
https://www.semanticscholar.org/paper/{id}
```

## API Access

```
https://api.semanticscholar.org/graph/v1/paper/{id}
```

Returns JSON with title, abstract, authors, citations, references, embeddings.

## Notes

- Paper IDs are 40-character hex strings (SHA1)
- Also accepts DOI, arXiv ID, ACM ID, etc. in API
- Free API with rate limits (1000 req/sec unauthenticated)
- Provides SPECTER2 embeddings for semantic similarity
- Good for citation analysis and paper discovery
- Aggregates from multiple sources
