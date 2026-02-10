# Repository Guidelines

## Project Structure & Module Organization
The repo is intentionally documentation-first. Root Markdown files (`README.md`, `SPEC.md`, `REGISTRY-GUIDE.md`, etc.) define the grammar, rationale, and contributor expectations. SecID namespaces live under `registry/<type>/<namespace>.md` and use YAML front matter plus narrative context—study existing entries such as `registry/advisory/mitre.md` before editing. Seed CSVs in `seed/*.csv` capture discovery lists (controls, references, vendors) that feed registry research; keep headers untouched and sorted alphabetically by name. Treat `TODO.md` and `ROADMAP.md` as authoritative for work in flight, and avoid creating parallel documents.

## Build, Test, and Development Commands
This repository has no compiled artifacts; the goal is clean, reviewable text. Use the commands below to keep contributions consistent:
- `rg -n "namespace: <name>" registry/<type>` — confirm you are not duplicating an existing namespace.
- `npx markdownlint-cli '**/*.md'` — lint Markdown (installs on demand via npx).
- `csvlint seed/seed-controls.csv` (or any edited CSV) — ensure seed files remain machine-consumable.

## Coding Style & Naming Conventions
Front matter fields are lower_snake_case with two-space indentation. Quote strings containing punctuation, and anchor `id_pattern` values (`^...$`) so they match complete identifiers. Body text uses sentence case headings, short paragraphs, and unordered lists to keep entries MIU (minimum interpretable unit). When referencing SecIDs, always use percent-encoding rules from `SPEC.md#82-percent-encoding` and mirror the source’s terminology—never invent alternative names or hierarchy.

## Testing Guidelines
Each registry addition needs: at least one example SecID, a lookup URL that returns the referenced item, and an `id_pattern` that validates actual IDs from the source. Before submitting, spot-check a handful of identifiers manually in the upstream site/API, verify that every example resolves, and ensure new CSV rows match the public spelling of the authority. Capture any edge cases or unresolved questions in `CONCERNS.md` so reviewers know what still needs validation.

## Commit & Pull Request Guidelines
Follow the existing short, imperative commit style (`Update CLAUDE.md with registry-required parsing rules`). Reference the touched file or concept in the subject, and keep each commit focused on a single change. Pull requests must link to the discussion issue, summarize why the change is needed, call out affected namespaces or seed files, and note any manual validation performed (e.g., “CVE lookup URL verified on 2024-03-11”). Include screenshots only when reasoning about external UIs; otherwise Markdown snippets suffice.
