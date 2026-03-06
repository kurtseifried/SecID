# Repository Guidelines

## Project Structure & Module Organization
- `registry/` is the source of truth for SecID namespaces and type definitions.
- `registry/<type>/...` stores namespace entries by reverse-domain path (for example, `registry/advisory/org/mitre.json`).
- `docs/` contains reference specs, contributor guides, design rationale, and operations documentation.
- `seed/` contains research CSV inputs only; do not treat these files as authoritative.
- `.github/workflows/update-registry.yml` dispatches updates to `SecID-Service` when `registry/**/*.json` changes on `main`.

## Build, Test, and Development Commands
This repository is primarily specification and registry data; there is no local app build.
- `rg --files registry docs seed` lists tracked content quickly.
- `python -m json.tool registry/<type>/<...>.json >/dev/null` validates JSON syntax for changed registry files.
- `rg -n "namespace:|\"namespace\"" registry/` checks namespace consistency and duplicates.
- `git diff -- registry/ docs/` reviews only relevant changes before opening a PR.

## Coding Style & Naming Conventions
- Use Markdown for docs and JSON for active registry namespace files.
- Keep Markdown concise, heading-driven, and instructional.
- Preserve existing key naming in JSON (for example, `schema_version`, `match_nodes`, `examples`).
- Follow reverse-domain path mapping for namespaces (for example, `mitre.org` -> `org/mitre`).
- Prefer small, focused edits; avoid broad reformatting unrelated to the change.

## Testing Guidelines
- There is no formal test suite in this repo today; validation is file-level and review-driven.
- For registry changes, verify:
  - JSON parses cleanly.
  - Example SecIDs and URL templates are internally consistent.
  - Regex/pattern updates do not broaden matching unintentionally.
- Include at least one concrete example in updated documentation when behavior changes.

## Commit & Pull Request Guidelines
- Match established commit style from history: imperative, concise subject lines (for example, `Add ...`, `Update ...`, `Convert ...`, `Rename ...`).
- Keep one logical change per commit and per PR.
- PRs should include:
  - What changed and why.
  - Affected paths/types (for example, `registry/advisory`, `docs/reference`).
  - Validation notes (commands run and results).
  - Linked issue/discussion when applicable.

## Security & Configuration Tips
- Do not commit secrets; this repo should remain content-only.
- Treat `seed/` as non-authoritative research input and migrate vetted data into `registry/`.
- If registry semantics change, update both docs and registry examples in the same PR.
