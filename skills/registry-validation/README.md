# registry-validation

**Status: Active — v0.1.** First non-stub skill in the SecID project.

## Purpose

Skill for **validating SecID registry `.json` and `.md` files** against structural, safety, consistency, and quality rules. Catches errors that manual review misses — from broken regex patterns to mismatched filesystem paths to dead variables in URL templates.

## Audience

- AI agents validating registry files during creation or review
- Human contributors checking their work before submitting PRs
- Future CI/CD pipelines (when this skill evolves into automated tooling)

## Pipeline Position

This skill sits between formalization and compliance-testing:

```
registry-research → registry-formalization → **registry-validation** → compliance-testing
```

- **Input:** One or more registry files (`.json` and/or `.md`)
- **Output:** A structured validation report with tiered findings (FAIL / WARN / INFO)

## What This Skill Covers

### Tier 1: Structural Validation (BLOCKING)

- File parses correctly (JSON / YAML frontmatter)
- Required fields present per format specification
- `type` is one of 8 valid values
- `status` uses correct values per format
- `namespace` passes per-segment validation regex
- Filesystem path matches namespace via reverse-DNS algorithm
- `match_nodes` structure is well-formed (JSON)

### Tier 2: Pattern Safety (BLOCKING)

- All regex patterns compile
- All patterns anchored with `^...$`
- ReDoS suspect detection (nested quantifiers, ambiguous alternation)
- Variable `extract` patterns have capture groups matching `format` references

### Tier 3: Consistency (WARNING)

- Examples match their declared patterns
- URL templates use only defined variables + builtins
- Dead variable detection
- Version resolution field consistency
- Lookup table key/pattern alignment
- ExampleObject URL verification

### Tier 4: Quality (ADVISORY)

- URLs are well-formed
- Match nodes have descriptions
- Examples exist at appropriate levels
- Metadata date format checks
- Null vs. absent convention consistency

## How to Use

See [PROMPT.md](PROMPT.md) for the complete validation prompt. Run it by providing one of:

- **Single file:** `validate registry/advisory/org/mitre.json`
- **Directory:** `validate registry/advisory/` (all .json and .md files)
- **Type:** `validate advisory` (entire type directory)

The prompt is self-contained — an AI agent can follow it without additional context.

## Wraps These References

This skill consolidates validation rules from:

- [docs/reference/REGISTRY-JSON-FORMAT.md](../../docs/reference/REGISTRY-JSON-FORMAT.md) — JSON schema specification (field requirements, match_nodes structure, variable extraction)
- [docs/reference/REGISTRY-FORMAT.md](../../docs/reference/REGISTRY-FORMAT.md) — YAML+Markdown format (frontmatter fields, sources block)
- [docs/guides/REGEX-WORKFLOW.md](../../docs/guides/REGEX-WORKFLOW.md) — Pattern anchoring, testing, ReDoS avoidance
- [docs/guides/REGISTRY-GUIDE.md](../../docs/guides/REGISTRY-GUIDE.md) — Null vs. absent convention, pattern quality standards

## Dependencies

- Python 3 (for regex compilation testing via `python3 -c "import re; ..."`)
- Access to the registry files being validated
- No external tools required; `recheck` recommended for thorough ReDoS analysis but not mandatory

## What This Skill Does NOT Cover

- **Resolver testing** — See [skills/compliance-testing/](../compliance-testing/) (tests that a resolver *implementation* produces correct URLs)
- **Source research** — See [skills/registry-research/](../registry-research/) (discovering and investigating new sources)
- **YAML-to-JSON conversion** — See [skills/registry-formalization/](../registry-formalization/) (converting .md files to .json)
- **URL liveness checks** — Requires network access; different concern
- **Cross-file consistency** — e.g., verifying entity references exist in other types (future scope)
- **Cross-format consistency** — e.g., verifying .md and .json for the same namespace agree (handled by registry-formalization)

## Design Rationale

**Why separate from formalization?** Formalization is about *producing* JSON from Markdown. Validation is about *checking* that any registry file (regardless of how it was produced) meets the rules. You can validate a hand-written JSON file that was never a Markdown file.

**Why tiered?** Not all findings are equal. A file that doesn't parse (Tier 1) is fundamentally broken. A missing description (Tier 4) is a quality improvement. Tiering lets users focus on what matters and prevents alert fatigue.

**Why agent-executable?** The validation prompt instructs agents to use `python3` for regex testing rather than attempting mental regex evaluation. This produces reliable results and catches real bugs.

**Relationship to CONVERSION-REVIEW-PROMPT.md:** The [registry/CONVERSION-REVIEW-PROMPT.md](../../registry/CONVERSION-REVIEW-PROMPT.md) covers review of YAML→JSON conversions specifically (data loss, field mapping, notes quality). This skill subsumes and extends the *structural and pattern* checks from that prompt, but does not replace the conversion-specific concerns (data loss detection, field mapping correctness). Use both when reviewing conversions; use this skill alone when validating standalone files.

## Open Questions

- Should Tier 3/4 checks be configurable (e.g., skip quality checks for draft entries)?
- Should the skill produce machine-readable output (JSON report) in addition to markdown?
- When should this evolve into a Python script or CI/CD action?
