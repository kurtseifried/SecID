# Repository Guidelines

## Project Structure & Module Organization
The root hosts strategy and specification papers (`SPEC.md`, `RATIONALE.md`, `STRATEGY.md`, etc.) that anchor every contribution. Canonical namespace definitions live under `registry/`; each type (advisory, entity, control, weakness, ttp, regulation, reference) has a summary file plus a directory of namespace markdown files that start with YAML frontmatter. Bulk bootstrap data sits in `seed/*.csv` and mirrors the taxonomy used in the registry. Use `_deferred/` inside `registry/` for partially researched systems so unfinished work does not block the published namespaces.

## Build, Test, and Development Commands
- `rg -n '^type:' registry/**/*.md` → quick audit that every registry file keeps mandatory metadata.
- `markdownlint **/*.md` → lint markdown and headings before opening a PR (use any markdownlint CLI; no config file means default rules).
- `git diff --stat && git diff --check` → review scope and catch stray whitespace in doc-heavy work.
- `column -t -s, seed/seed-controls.csv | head` → spot-check CSV structure after edits without opening a spreadsheet.

## Coding Style & Naming Conventions
Write Markdown with clear headings, fenced code blocks for SecID examples, and tables for enumerations. Registry files must begin with YAML frontmatter containing at least `type`, `namespace`, `name`, and a descriptive title, followed by narrative guidance. The registry directory structure mirrors SecID identifiers: `registry/<type>/<namespace>/<name>.md` (e.g., `registry/advisory/mitre/cve.md` for `secid:advisory/mitre/cve`). Keep filenames lowercase with hyphens. Encode reserved characters inside identifiers exactly as described in `SPEC.md` (e.g., `A&A-01` → `A%26A-01`).

## Testing Guidelines
There is no automated test harness yet, so rely on tight manual checks. Ensure new namespaces include at least one `secid:` example plus resolution instructions. Validate CSV edits with the `column` preview above or any CSV validator to confirm column counts stay stable.

## Commit & Pull Request Guidelines
Recent history favors short, action-oriented commit subjects (e.g., “Add project housekeeping files”). Keep each commit focused on a single namespace or document. Every PR should describe the impacted identifiers, reference relevant spec sections, and note data sources; attach screenshots only when visual diffs are meaningful. Link to an issue or open a discussion thread before introducing new identifier types so reviewers can align registry, seed data, and roadmap expectations.

## Security & Data Handling Tips
Never add proprietary or embargoed advisories; stick to public identifiers. Cite authoritative registries (CVE, CWE, NIST, etc.) and include URLs in the markdown body so automated agents can trace sources. For CSV seed imports, scrub sensitive columns and prefer IDs over free-form personal data.
