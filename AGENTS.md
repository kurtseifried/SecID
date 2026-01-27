# Repository Guidelines

## Project Structure & Module Organization
Specification papers (`SPEC.md`, `RATIONALE.md`, `STRATEGY.md`, etc.) live at the root—skim them before touching the registry. Canonical namespaces sit under `registry/` and mirror SecID identifiers (`registry/<type>/<namespace>/<name>.md`). Each type (advisory, entity, control, weakness, ttp, regulation, reference) has a summary file plus namespaced Markdown with YAML frontmatter. Seed CSVs in `seed/` mirror that taxonomy, while `_deferred/` holds incomplete research to keep published namespaces stable.

## Build, Test, and Development Commands
- `rg -n '^type:' registry/**/*.md` verifies every registry entry keeps mandatory metadata blocks.
- `markdownlint **/*.md` applies default lint rules so prose formatting remains predictable.
- `git diff --stat && git diff --check` reviews scope and blocks stray whitespace before committing.
- `column -t -s, seed/seed-controls.csv | head` spot-checks CSV column alignment without opening spreadsheets.

## Coding Style & Naming Conventions
Keep Markdown concise with clear headings, fenced SecID examples, and tables for enumerations. Registry files must start with YAML frontmatter containing `type`, `namespace`, `name`, and a descriptive title, followed by narrative guidance and at least one `secid:` example. Filenames stay lowercase-with-hyphens; encode reserved identifier characters exactly as shown in `SPEC.md` (e.g., `A&A-01` → `A%26A-01`).

## Testing Guidelines
There is no automated harness yet. Manually review new namespaces for cross-links, examples, and resolution instructions. Validate CSV edits with the `column` preview or another validator to maintain column counts. Before pushing, rerun `rg`/`markdownlint` to ensure metadata blocks and headings remain consistent.

## Commit & Pull Request Guidelines
Follow the recent style of short, action-oriented commit subjects (e.g., "Add project housekeeping files") and keep each commit scoped to a single namespace or document. PRs should describe impacted identifiers, cite relevant spec sections, and link discussions before adding new identifier types. Call out data sources, attach screenshots only when visual review is necessary, and mention any manual validation performed.

## Security & Data Handling Tips
Restrict contributions to public identifiers; never add embargoed advisories. Cite authoritative registries (CVE, CWE, NIST, etc.) and include URLs so automated agents can verify provenance. Scrub sensitive columns from seed data and favor durable IDs over free-form personal details when importing external records.
