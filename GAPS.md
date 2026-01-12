# Documentation Gap Analysis

This document provides a gap analysis of the SecID project documentation based on a review of all `.md` files in the repository. It focuses on four key areas: Governance, Registry Maintenance, Tooling, and Future Layers.

---

### 1. Governance

#### What the Documentation Says
*   **Stewardship:** The project is explicitly a "project of the Cloud Security Alliance" (`README.md`), and `STRATEGY.md` names the CSA as the steward, chosen for its non-profit status and global scope.
*   **Governance Model:** `STRATEGY.md` names the model as "Benevolent Dictator" and mentions a "SecID Working Group."
*   **Philosophy:** `RATIONALE.md` states a philosophy of "Guidelines, not rules" to remain flexible and avoid getting bogged down.
*   **Contributions:** `CONTRIBUTING.md` outlines the standard GitHub process (Issues, Forks, PRs) for proposing changes.

#### Identified Gaps

*   **~~Undefined "Benevolent Dictator"~~** ✅ **RESOLVED**: Kurt Seifried is named as BDFL in `STRATEGY.md`. Succession planning deferred until community growth warrants it.
*   **Vague Working Group Charter:** The "SecID Working Group" is mentioned, but its charter, membership criteria, meeting cadence, and decision-making processes are not defined. *Accepted: Working group will be established when community interest warrants it.*
*   **No Formal Dispute Resolution Process:** The "Guidelines, not rules" philosophy is excellent for agility but does not provide a mechanism for resolving conflicts. *Accepted for now: BDFL decides. Formal process when needed.*
*   **Lack of a Formal Change Control Process:** While `CONTRIBUTING.md` describes how to submit a PR, there is no formal process described for how changes to the core `SPEC.md` are evaluated, approved, and versioned. *Accepted: BDFL approves spec changes. Formal RFC process when community grows.*

---

### 2. Registry Maintenance

#### What the Documentation Says
*   **How to Contribute:** `CONTRIBUTING.md` explains that new registry additions and corrections should be submitted via GitHub pull requests.
*   **Curation Strategy:** `STRATEGY.md` mentions an initial plan: "Curation: Initially by core team, eventually by community."
*   **Seeding Plan:** `ROADMAP.md` has a detailed "Registry Seeding Strategy," showing a clear plan to populate the registry with thousands of entities in phases.

#### Identified Gaps
*   **Undefined Path to Community Curation:** The transition from a "core team" to "community" curation is a critical step for long-term health, but the process, criteria for community curators, and timeline are not defined. *Accepted: Will define when community grows.*
*   **No Service Level Objectives (SLOs):** There are no stated goals or expected timelines for how quickly new proposals (like a new namespace) will be reviewed or merged. *Accepted: Early stage project, best-effort response times.*
*   **~~No Deprecation or Archival Process~~** ✅ **RESOLVED**: Documented in `DESIGN-DECISIONS.md` under "Namespace Transitions: Case by Case". Key decisions: (1) Old identifiers are forever, (2) Retired standards are enrichment data not namespace changes, (3) Handle transitions when they happen with real information.

---

### 3. Tooling Ecosystem

#### What the Documentation Says
*   **Explicitly Out of Scope for v1.0:** `STRATEGY.md` is very clear: "Reference implementations are out of scope for v1.0." The strategy is to focus on a solid specification and let the community build tools.
*   **Library Roadmap:** `ROADMAP.md` lists a clear priority order for official libraries they *plan* to build after v1.0 is complete (Python first, then JS/TS, then a REST API, etc.).
*   **PURL Parity:** `RATIONALE.md` suggests that existing PURL libraries can be adapted, lowering the barrier for developers.

#### Identified Gaps
*   **No Central Discovery Hub:** There is no file or plan mentioned for creating a central place (like an "awesome-secid" list) to track community-built tools. This makes it hard for new adopters to find implementations.
*   **No Compliance or Testing Suite:** The documentation does not mention the creation of an official test suite. Without a set of canonical test cases, different implementations might have subtle inconsistencies in how they parse or handle edge cases (like complex percent-encoding or subpath interpretation). This could lead to fragmentation.

---

### 4. Complexity of Future Layers (Relationships & Overlays)

#### What the Documentation Says
*   **Explicitly Deferred:** This is the most clearly communicated point. `RELATIONSHIPS.md`, `OVERLAYS.md`, `DESIGN-DECISIONS.md`, and `ROADMAP.md` all state that these layers are **intentionally not designed yet**.
*   **Reasoning is Clear:** The rationale is to "avoid premature complexity" and let real-world usage of the v1.0 spec inform the design of these more complex layers.
*   **Exploratory Ideas:** The `RELATIONSHIPS.md` and `OVERLAYS.md` files serve as public sketches of the problems to be solved, including potential relationship types (`aliases`, `mitigates`) and the key unsolved challenges (conflict resolution, provenance, trust).

#### Identified Gaps
*   **The Entire Design is the Gap:** The project is transparent that this is a "known unknown." The documentation contains high-level ideas but does not yet tackle the difficult questions it raises (e.g., how to resolve conflicting overlay data from two trusted sources).
*   **No Trigger Criteria for Starting Design:** The documents state that design will begin "when we have concrete use cases," but this is not defined with specific metrics. It's unclear what level of adoption or what specific events will trigger the formal design and implementation of these critical future layers.

---

## Tactical and Technical Gaps (and Resolutions)

This section details lower-level technical and implementation concerns identified during review, along with the strategic decisions made for each. It is intended to provide context for future development.

### 1. Parsing and Subpath Interpretation
*   **Initial Concern:** The flexibility of percent-encoding and subpath structures could lead to inconsistent parser implementations. A generic parser cannot know how to validate a subpath without context.
*   **Discussion & Decision:** This is a valid concern. The decision is that the system must be self-describing.
*   **Actionable Gap:** The `SPEC.md` or `CONTRIBUTING.md` must be updated to make it a formal requirement that any registry file defining a `name` (e.g., `cve.md`, `ccm.md`) **must** also define the validation rules (`id_pattern`) and parsing logic for its corresponding subpaths.

### 2. URL Rot and Data Availability
*   **Initial Concern:** The resolution system depends on `url_template` links that will inevitably break over time as external websites change.
*   **Discussion & Decision:** This is a critical long-term problem. The strategy to mitigate this is to not rely on the live URL forever. The project will endeavor to cache/store a point-in-time copy of the data that a URL resolves to, making the system more resilient.
*   **Actionable Gap:** The `ROADMAP.md` or `STRATEGY.md` does not currently include this data preservation and caching strategy. This should be documented to clarify the long-term vision.

### 3. Data and Tooling Validation
*   **Initial Concern:** There is no documented process for validating the quality of seed data or for testing the compliance of third-party tools.
*   **Discussion & Decision:** This was confirmed as a critical gap. Data quality and implementation consistency are paramount. The plan is to use AI for validating seed data and the resulting generated files. Furthermore, a testing framework is needed for the ecosystem.
*   ✅ **RESOLVED:** AI-assisted validation strategy documented in `ROADMAP.md`. Workflow: (1) Ask AI what users would do with a SecID, (2) Codify that as the goal, (3) Add resolution rules, (4) AI verifies it works. AI is a first-class team member for validation at scale.

### 4. API and Data Distribution Model
*   **Initial Concern:** The default Git-based model is too heavy for simple tools, and a REST API creates a central dependency.
*   **Discussion & Decision:** The scalability model will be twofold. (1) To mitigate the "heavy repo" problem, the project will generate and provide a single, consolidated data file (e.g., a SQLite database or a comprehensive JSON file) for easy download. (2) The future REST API will be designed to be self-hostable, so users are not dependent on a single central service.
*   **Actionable Gap:** The `ROADMAP.md` and `STRATEGY.md` should be updated to explicitly mention these two key distribution mechanisms.

### 5. Short-Term Accepted Trade-offs
Several other technical concerns were deemed to be acceptable trade-offs for the initial, file-system-based version of the project. The long-term solution for these is a move to a more robust data storage system. These are noted here for context but are not considered immediate gaps to be fixed.
*   **Percent-Encoding Complexity:** Acknowledged as a "necessary evil" for now to support a wide range of identifiers on standard filesystems.
*   **Filesystem Path Length Limits:** A known limitation of the current approach that will be resolved by a future database/storage solution.
*   **Database Indexing Strategy:** Not a concern at the current scale. Will be addressed when a formal storage solution is designed.

---

### Summary

The project documentation is exceptionally transparent about what it is and what it isn't. The most significant strategic gaps are not accidental omissions but rather deliberate, documented decisions to defer complexity.

**Resolved since initial analysis:**
- ✅ Governance: Kurt Seifried named as BDFL in `STRATEGY.md`
- ✅ PURL constraint documented as governance mechanism
- ✅ Namespace transitions: Case-by-case approach documented in `DESIGN-DECISIONS.md`
- ✅ Validation strategy: AI-assisted workflow documented in `ROADMAP.md`

**Remaining gaps (intentionally deferred):**
- Working group charter (establish when community grows)
- Formal dispute resolution (BDFL decides for now)
- SLOs for PR review (best-effort at early stage)
- URL rot mitigation (future content caching addresses this)
- Compliance test suite (needed before v1.0 libraries ship)