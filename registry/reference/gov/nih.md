---
namespace: nih.gov
full_name: "PubMed"
type: reference

urls:
  website: "https://pubmed.ncbi.nlm.nih.gov"
  lookup: "https://pubmed.ncbi.nlm.nih.gov/{id}/"
  api: "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?db=pubmed&id={id}"

id_pattern: "\\d+"
examples:
  - "35298662"
  - "33119447"

status: draft
---

# PubMed Namespace

PubMed - NIH's database of biomedical and life sciences literature.

## Format

```
secid:reference/nih.gov/{pmid}
secid:reference/nih.gov/35298662
```

## Resolution

```
https://pubmed.ncbi.nlm.nih.gov/{id}/
```

## Security Relevance

While primarily biomedical, PubMed covers:
- Healthcare cybersecurity
- Medical device security
- Health data privacy
- Biometric security research
- Human factors in security

## Notes

- PMIDs are simple numeric identifiers
- Free access to abstracts; full text varies
- PubMed Central (PMC) has free full-text subset
- DOIs also available for most papers
- Operated by National Library of Medicine (NIH)
