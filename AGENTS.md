# Repository Guidelines

## Project Structure & Module Organization
The repository is documentation-first: Markdown specs and design notes live at the root (`README.md`, `SPEC.md`, `DESIGN-DECISIONS.md`), the authoritative registry sits in `registry/`, and research CSVs are staged under `seed/`. Registry entries follow `registry/<type>/<tld>/<domain>.md`, so `registry/control/gov/nist.md` defines every `secid:control/nist.gov/*` namespace. JSON mirrors exist where automation is being trialed (for example `registry/control/org/cloudsecurityalliance.json`); keep Markdown and JSON neighbors in sync. Treat `seed/*.csv` files as research scratchpads only—promote vetted sources into the registry with rich narrative context per `REGISTRY-FORMAT.md`.

## Build, Test, and Development Commands
There is no compile pipeline, but two quick checks keep contributions sane: `rg -n 'namespace:' registry/control` locates precedents so new namespaces fit existing patterns, and `python -m json.tool registry/control/org/cloudsecurityalliance.json` validates any JSON mirrors before committing. Run `git status -sb` prior to a PR to ensure you are only touching intentional files.

## Coding Style & Naming Conventions
Registry files must open with YAML frontmatter delimited by `---`, indented with two spaces, and use lower-case reverse-DNS namespaces (`mitre.org`, `cloudsecurityalliance.org`). Markdown headings should mirror the source name (`# MITRE Advisory Sources`) and include example SecIDs like ``secid:advisory/mitre.org/cve#CVE-2024-1234``. Keep CSV headers untouched and prefer snake_case column names. When text calls out identifiers, quote them with backticks to help toolchains parse references.

## Testing Guidelines
Before submitting, manually resolve every example SecID you add to confirm lookup URLs and regexes. Run a spelling/formatting pass (e.g., `rg -n 'TODO' registry`) to ensure drafts are not promoted accidentally. If you edit a seed CSV, spot-check that its contents already exist—or intentionally do not yet exist—in `registry/` so agents know whether data is authoritative. There are no coverage targets, but each new namespace needs at least one concrete example plus resolution instructions.

## Commit & Pull Request Guidelines
Follow the pattern already in Git history: short imperative subject lines (`Add CSA CCM sources`) and one logical change per commit. Reference related issues in the PR description, note whether you touched Markdown, JSON, or CSV assets, and call out any new identifier patterns or lookup rules. PRs should list screenshots only when UI output is relevant (rare here) but must always summarize added namespaces or documents and link to their sources for reviewer verification.
