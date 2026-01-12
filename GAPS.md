# Documentation Gap Analysis

This document tracks gaps identified in SecID project documentation and their resolution status.

---

## Status Summary

### Resolved ✅

| Gap | Resolution | Where Documented |
|-----|------------|------------------|
| Undefined BDFL | Kurt Seifried named as BDFL | `STRATEGY.md` |
| PURL governance constraint | Documented as intentional constraint that inherits PURL decisions | `STRATEGY.md` |
| Deprecation/archival process | Case-by-case approach; old identifiers forever; retired standards are enrichment data | `DESIGN-DECISIONS.md` |
| Data validation strategy | AI-assisted validation workflow | `ROADMAP.md` |
| API/distribution model | REST API + libraries in priority order; self-hostable design | `ROADMAP.md` |

### Intentionally Deferred ⏸️

| Gap | Rationale | Trigger to Address |
|-----|-----------|-------------------|
| Working group charter | Premature governance complexity kills projects | When community interest warrants formal input |
| Formal dispute resolution | BDFL decides for now | When disputes actually arise that need process |
| SLOs for PR review | Early stage, small team | When contributor volume requires predictability |
| Path to community curation | Need core team experience first | When registry is stable and patterns are clear |
| Future layers design (relationships, overlays) | Intentionally deferred to learn from usage | When v1.0 has real adoption and concrete use cases |

### Still Open 🔴

| Gap | Priority | What's Needed |
|-----|----------|---------------|
| Compliance test suite | High | Canonical test cases before libraries ship to prevent implementation drift |
| Registry file validation requirement | Medium | SPEC.md or CONTRIBUTING.md should require `id_pattern` in all registry files |
| Central discovery hub | Low | "awesome-secid" list or similar for community tools |
| URL rot mitigation details | Low | Content caching strategy (addressed conceptually by v1.x raw content phase) |

---

## Detailed Analysis

### 1. Governance

#### Current State
- **BDFL**: Kurt Seifried (documented in `STRATEGY.md`)
- **Stewardship**: Cloud Security Alliance
- **Philosophy**: "Guidelines, not rules" for agility
- **PURL Constraint**: We inherit PURL's decisions on identifier syntax, focusing governance energy on security-specific questions

#### Resolved
- ✅ BDFL named explicitly
- ✅ PURL compatibility framed as governance mechanism

#### Deferred (Acceptable)
- ⏸️ Working group charter - establish when needed
- ⏸️ Formal dispute resolution - BDFL decides for now
- ⏸️ Change control process for SPEC.md - BDFL approves, formal RFC when community grows

---

### 2. Registry Maintenance

#### Current State
- Contribution via GitHub PRs (`CONTRIBUTING.md`)
- Seeding strategy documented (`ROADMAP.md`)
- AI-assisted validation workflow defined

#### Resolved
- ✅ Deprecation/archival: "Namespace Transitions: Case by Case" in `DESIGN-DECISIONS.md`
  - Old identifiers are forever
  - Retired standards = enrichment data, not namespace changes
  - Handle transitions when they happen with real information
- ✅ Validation strategy: AI-assisted workflow in `ROADMAP.md`

#### Deferred (Acceptable)
- ⏸️ Path to community curation - define when community grows
- ⏸️ SLOs for PR review - best-effort at early stage

---

### 3. Tooling Ecosystem

#### Current State
- Library roadmap defined: Python → npm → REST API → Go → Rust → Java → C#/.NET
- PURL library adaptation possible (lowers barrier)

#### Still Open
- 🔴 **Compliance test suite** (HIGH PRIORITY)
  - Without canonical test cases, implementations may handle edge cases differently
  - Needed before v1.0 libraries ship
  - Should cover: percent-encoding, subpath parsing, version handling, qualifier parsing

- 🔴 **Central discovery hub** (LOW PRIORITY)
  - No "awesome-secid" list planned
  - Would help adopters find community tools
  - Can add when there are tools to list

---

### 4. Future Layers (Relationships & Overlays)

#### Current State
- Explicitly deferred - documented in `RELATIONSHIPS.md`, `OVERLAYS.md`, `DESIGN-DECISIONS.md`
- Exploratory ideas captured but not committed
- Rationale: avoid premature complexity, let usage inform design

#### Deferred (Intentional)
- ⏸️ Entire relationship layer design
- ⏸️ Entire overlay layer design
- ⏸️ Trigger criteria for starting design

This is the correct approach. Designing these layers before v1.0 adoption would be guessing.

---

### 5. Technical Gaps

#### Resolved
- ✅ **Data validation**: AI-assisted workflow documented
- ✅ **API distribution**: REST API + self-hostable in roadmap

#### Still Open
- 🔴 **Registry file validation requirement** (MEDIUM PRIORITY)
  - Registry files should be required to include `id_pattern` for subpath validation
  - Should be added to SPEC.md or CONTRIBUTING.md

- 🔴 **URL rot mitigation** (LOW PRIORITY)
  - Conceptually addressed by v1.x raw content caching
  - Detailed strategy not yet documented
  - Will become clearer as content ingestion begins

#### Accepted Trade-offs
- Percent-encoding complexity (necessary evil)
- Filesystem path length limits (future database solves)
- Database indexing (not a concern at current scale)

---

## Next Actions

1. **Before v1.0 libraries ship**: Create compliance test suite with canonical test cases
2. **During registry buildout**: Ensure all registry files include `id_pattern`
3. **When community grows**: Establish working group, formalize processes
4. **When v1.0 has adoption**: Begin relationship/overlay layer design with real use cases
