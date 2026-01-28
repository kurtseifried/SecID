---
namespace: iacr
full_name: "IACR Cryptology ePrint Archive"
type: reference

urls:
  website: "https://eprint.iacr.org"
  lookup: "https://eprint.iacr.org/{id}"
  pdf: "https://eprint.iacr.org/{id}.pdf"

id_pattern: "\\d{4}/\\d+"
examples:
  - "2024/001"
  - "2023/1234"
  - "2020/1110"

status: draft
---

# IACR ePrint Namespace

The Cryptology ePrint Archive - the primary preprint server for cryptography research. Essential for security research.

## Format

```
secid:reference/iacr/{year}/{number}
secid:reference/iacr/2024/001
```

## Resolution

```
https://eprint.iacr.org/{id}
https://eprint.iacr.org/{id}.pdf
```

## Security-Relevant Papers

| ID | Title | Topic |
|----|-------|-------|
| 2020/1110 | Plonk | ZK proofs |
| 2016/260 | Groth16 | ZK-SNARKs |
| 2023/939 | Jolt | ZK-SNARKs |

## Notes

- Format: YYYY/NNNNN (year/sequence number)
- Not peer-reviewed, but widely cited
- Primary source for cutting-edge cryptography research
- Covers: encryption, signatures, ZK proofs, MPC, post-quantum crypto
- Operated by International Association for Cryptologic Research
