# Registry Validation Prompt

You are validating SecID registry files against the project's structural, safety, consistency, and quality rules. Follow this prompt step by step.

## Setup

**Before validating any files, read these reference documents:**

1. `docs/reference/REGISTRY-JSON-FORMAT.md` — The JSON schema specification (authority on JSON field requirements, match_nodes structure, variable extraction, version resolution)
2. `docs/reference/REGISTRY-FORMAT.md` — The YAML+Markdown format (authority on frontmatter fields, sources block, status values)
3. `docs/guides/REGISTRY-GUIDE.md` — Quality standards (null vs. absent convention, pattern guidance)

These documents define what "correct" means. Do not rely on memory — read them.

## Input

Accept one of these input modes:

- **Single file:** A path to a `.json` or `.md` registry file
- **Directory:** A path to a directory (validate all `.json` and `.md` files within, excluding `_template.md` and `_deferred/`)
- **Type keyword:** One of `advisory`, `weakness`, `ttp`, `control`, `disclosure`, `regulation`, `entity`, `reference` (validate all files under `registry/<type>/`)

## Important: Use Tools, Not Mental Evaluation

**Use `python3 -c "import re; ..."` to test regex patterns.** Do not try to evaluate regex matches in your head — you will make mistakes. Every pattern compilation check and every example-vs-pattern match must be verified with actual code execution.

## Validation Tiers

Validate each file through all applicable tiers. Stop and report if Tier 1 fails (the file is unparseable — later tiers cannot run).

---

### Tier 1: Structural Validation (BLOCKING)

A Tier 1 failure means the file is fundamentally broken. Result: **FAIL** or **PASS**.

#### For `.json` files:

**T1.1 — File parses as valid JSON.**
```bash
python3 -c "import json; json.load(open('FILEPATH'))"
```

**T1.2 — Required fields present.** Check for:
- `schema_version` (must equal `"1.0"`)
- `namespace` (string)
- `type` (string)
- `status` (string)
- `official_name` (string)
- Either `match_nodes` (array) OR `alias_of` (string) — alias stubs have `alias_of` instead of `match_nodes`

**T1.3 — `type` is valid.** Must be one of: `advisory`, `weakness`, `ttp`, `control`, `disclosure`, `regulation`, `entity`, `reference`.

**T1.4 — `status` is valid.** Must be one of: `proposed`, `draft`, `pending`, `published`.

**T1.5 — `namespace` per-segment validation.** Split namespace on `/`. Each segment must match:
```
^[\p{L}\p{N}]([\p{L}\p{N}._-]*[\p{L}\p{N}])?$
```
Test with:
```bash
python3 -c "
import re
segments = 'NAMESPACE'.split('/')
pattern = re.compile(r'^[\w]([\w._-]*[\w])?$', re.UNICODE)
for s in segments:
    if not pattern.match(s):
        print(f'FAIL: segment \"{s}\" does not match')
    else:
        print(f'OK: segment \"{s}\"')
"
```

**T1.6 — Filesystem path matches namespace.** Given the file's actual path and its declared `namespace` and `type`, verify they agree using this algorithm:

1. Split namespace at first `/` → domain part, path part (if any)
2. Split domain on `.` → segments
3. Reverse segments → TLD-first directory path
4. Append path part (if any)
5. Append `.json` (or `.md`)
6. Prepend `registry/<type>/`

**Worked example:**
- Namespace: `github.com/advisories`, Type: `advisory`
- Domain: `github.com`, Path: `advisories`
- Split domain: `github`, `com` → Reverse: `com/github`
- Append path: `com/github/advisories`
- Expected: `registry/advisory/com/github/advisories.json`

**Simple example:**
- Namespace: `mitre.org`, Type: `advisory`
- Domain: `mitre.org`, no path
- Split: `mitre`, `org` → Reverse: `org/mitre`
- Expected: `registry/advisory/org/mitre.json`

**T1.7 — `match_nodes` structure.** (Skip for alias stubs.) `match_nodes` must be an array. Each node must have a `patterns` array with at least one string entry. Recurse into `children` — same rule applies at every level.

```bash
python3 -c "
import json

def check_nodes(nodes, path='match_nodes'):
    if not isinstance(nodes, list):
        print(f'FAIL: {path} is not an array')
        return
    for i, node in enumerate(nodes):
        p = f'{path}[{i}]'
        patterns = node.get('patterns')
        if not patterns or not isinstance(patterns, list) or len(patterns) == 0:
            print(f'FAIL: {p} has no patterns array or it is empty')
        else:
            print(f'OK: {p} has {len(patterns)} pattern(s)')
        children = node.get('children')
        if children:
            check_nodes(children, f'{p}.children')

data = json.load(open('FILEPATH'))
if 'match_nodes' in data:
    check_nodes(data['match_nodes'])
elif 'alias_of' not in data:
    print('FAIL: neither match_nodes nor alias_of found')
"
```

#### For `.md` files:

**T1.1md — File has valid YAML frontmatter.** Must start with `---`, contain YAML, end with `---`.
```bash
python3 -c "
import yaml
with open('FILEPATH') as f:
    content = f.read()
if not content.startswith('---'):
    print('FAIL: no YAML frontmatter')
else:
    end = content.index('---', 3)
    data = yaml.safe_load(content[3:end])
    print('OK: YAML parses successfully')
    print(f'Fields: {list(data.keys())}')
"
```

**T1.2md — Required fields present.** Check for: `type`, `namespace`, `full_name`.

**T1.3md — `type` is valid.** Same 8 values as JSON.

**T1.4md — `status` is valid (if present).** Must be one of: `active`, `draft`, `superseded`, `historical`.

**T1.5md — `namespace` per-segment validation.** Same check as JSON T1.5.

**T1.6md — Filesystem path matches namespace.** Same algorithm as JSON T1.6, but with `.md` extension.

---

### Tier 2: Pattern Safety (BLOCKING)

A Tier 2 failure means patterns are dangerous or broken. Result: **FAIL** or **PASS**.

**T2.1 — All patterns compile.** For JSON, extract every `patterns` array entry from `match_nodes` (recursive). For YAML, extract `id_pattern` and `id_patterns` from `sources`. Test each:
```bash
python3 -c "import re; re.compile(r'PATTERN')"
```

**T2.2 — All patterns are anchored.** Each pattern must start with `^` (or `(?i)^` or `(?...)^`) and end with `$`. This prevents partial matches.

Exception: Patterns that are purely literal and case-insensitive name matches (like `(?i)^cve$`) are fine as-is.

**T2.3 — ReDoS suspect detection.** Flag patterns containing any of these constructs:
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`
- Ambiguous alternation with quantifiers: `(a|a)+`, `(a|ab)+`
- Wide wildcards in repeated groups: `(.*a)+`

These are WARNINGS, not automatic failures. Note: "Use the `recheck` tool for thorough analysis if available."

**T2.4 — Variable extraction consistency.** For each node with a `variables` object:
- Each variable's `extract` pattern must compile
- Each variable's `extract` pattern must have at least as many capture groups as referenced in `format` (default `{1}`)
- Every variable referenced in `url_template` (as `{varname}`) must be defined in `variables` (except builtins: `{id}`, `{version}`, `{item_version}`, `{lang}`)
- The `extract` pattern must be anchored

```bash
python3 -c "
import re
pattern = re.compile(r'EXTRACT_PATTERN')
print(f'Groups: {pattern.groups}')
# Check that format references like {1}, {2} don't exceed group count
"
```

---

### Tier 3: Consistency (WARNING)

Tier 3 findings indicate likely bugs but don't make the file unusable. Result: **WARN** or **PASS**.

**T3.1 — Examples match their patterns.** For each example at the child/subpath level (JSON `data.examples`), if the example is a structured ExampleObject with an `input` field, test the input against the node's pattern. For bare string examples at the source level, skip this check (they're representative samples, not test fixtures).

```bash
python3 -c "
import re
pattern = re.compile(r'PATTERN')
result = pattern.match('EXAMPLE_INPUT')
print(f'Match: {result is not None}')
"
```

**T3.2 — URL template variables are defined.** Extract all `{placeholder}` references from every `url_template` and `url` field. Each must be either:
- A builtin: `{id}`, `{version}`, `{item_version}`, `{lang}`
- Defined in the node's `variables` object
- Defined in a `lookup_table`

**T3.3 — No dead variables.** Every variable defined in `variables` should be referenced in at least one `url_template` or `url` field in the same node or its parent chain. Unreferenced variables are likely copy-paste errors.

**T3.4 — Version resolution consistency.** If `version_required` is `true`:
- `unversioned_behavior` should exist (describes what happens when `@version` is omitted)
- `version_disambiguation` should exist (guides version selection)

**T3.5 — Lookup table keys match patterns.** For each `lookup_table`, the keys should match the pattern of the node they belong to. Test a sample:
```bash
python3 -c "
import re
pattern = re.compile(r'PATTERN')
keys = ['KEY1', 'KEY2', 'KEY3']  # sample keys
for k in keys:
    if not pattern.match(k):
        print(f'WARN: lookup key \"{k}\" does not match pattern')
"
```

**T3.6 — Weights are numeric and in range.** All `weight` values must be numbers in the range 0–200.

**T3.7 — Status completeness.** For JSON files with status `pending` or `published`:
- Fields should not be absent (though `null` is fine — it means "we looked, nothing to find")
- This is a soft check: warn on absent fields, don't fail

**T3.8 — ExampleObject URL verification.** For structured examples with `url` fields, check that substituting variables from `input` into the node's `url_template` produces the declared `url`.

**T3.9 — YAML sources block.** For `.md` files, each entry in `sources` should have:
- `full_name` (string)
- `urls` (map with at least one entry)

#### For `.md` files, also check:

**T3.10md — id_pattern compiles and is anchored.** Same as T2.1 and T2.2 but for `id_pattern` / `id_patterns` fields in the YAML sources block.

---

### Tier 4: Quality (ADVISORY)

Tier 4 findings are suggestions for improvement. Result: **INFO** or **PASS**.

**T4.1 — URLs are well-formed.** Check that URL strings in `urls`, `url_template`, `url`, and `lookup_table` values start with `http://` or `https://` and contain no spaces.

**T4.2 — Match nodes have descriptions.** Every node in `match_nodes` should have a `description` field. Missing descriptions make the registry harder for humans and AI agents to understand.

**T4.3 — Examples exist.**
- Source-level (name nodes): should have `data.examples` (bare strings showing representative SecID usage)
- Child-level (subpath nodes): should have `data.examples` (structured ExampleObjects that serve as test fixtures)

**T4.4 — Metadata dates are ISO 8601.** Check that `_checked` and `_updated` suffix fields (e.g., `urls_checked`, `match_nodes_updated`) use `YYYY-MM-DD` format.

**T4.5 — Null vs. absent consistency.** Within a single file, the convention should be consistent:
- Fields explicitly set to `null` should have `_checked` metadata when possible
- There shouldn't be a mix of `null` (researched, empty) and absent (not researched) for fields at the same level without good reason

**T4.6 — Lookup table provenance.** If `lookup_table` exists, it should have a `provenance` object with at least `method` and `date` fields.

**T4.7 — Notes for published entries.** Files with status `pending` or `published` benefit from having a top-level `notes` field explaining operational context.

---

## Report Format

After completing validation, output a structured report.

### Single-File Report

```markdown
# Validation Report: {filename}
Date: {YYYY-MM-DD}

## Summary
| Tier | Result | Findings |
|------|--------|----------|
| 1: Structural     | PASS/FAIL | {count} |
| 2: Pattern Safety | PASS/FAIL | {count} |
| 3: Consistency    | PASS/WARN | {count} |
| 4: Quality        | PASS/INFO | {count} |

Overall: PASS / FAIL / WARN

## Findings

### Tier 1: Structural
- [PASS] All structural checks passed.

### Tier 2: Pattern Safety
- [FAIL] T2.1: Pattern `(unclosed` at match_nodes[0].children[2] does not compile: missing closing parenthesis
- [PASS] T2.2: All patterns anchored.

### Tier 3: Consistency
- [WARN] T3.1: Example "CVE-2024-ABC" does not match pattern `^CVE-\d{4}-\d{4,}$` at match_nodes[0].children[0]
- [WARN] T3.3: Variable "bucket" defined but not referenced in any URL template

### Tier 4: Quality
- [INFO] T4.2: Node at match_nodes[0] has no description
- [INFO] T4.3: No examples at match_nodes[0].children[1]
```

Use `[FAIL]`, `[WARN]`, or `[INFO]` prefixes. Include the check ID (e.g., T2.1) and the location in the file (e.g., `match_nodes[0].children[2]`).

### Batch Report

When validating multiple files, prepend a summary table:

```markdown
# Batch Validation Report
Date: {YYYY-MM-DD}
Files: {count}

## Summary
| File | T1 | T2 | T3 | T4 | Overall |
|------|----|----|----|----|---------|
| advisory/org/mitre.json | PASS | PASS | PASS | 2 INFO | PASS |
| advisory/com/redhat.json | PASS | PASS | 1 WARN | PASS | WARN |
| weakness/org/owasp.json | PASS | PASS | PASS | PASS | PASS |

## Per-File Reports
[Individual reports follow, using the single-file format above]
```

### Overall Result Logic

- **FAIL** if any Tier 1 or Tier 2 check fails
- **WARN** if any Tier 3 check triggers a warning (but no Tier 1/2 failures)
- **PASS** if only Tier 4 advisories (or nothing at all)

---

## Edge Cases

### Alias stubs
Files with `alias_of` (JSON) or `alias_of` (YAML) are minimal — they have no `match_nodes` or `sources`. Validate only: T1.1–T1.6 (structural), T1.2 checks for `alias_of` instead of `match_nodes`/`sources`. Skip Tiers 2–4.

### Entity type
Entity files use `match_nodes` with literal patterns (e.g., `(?i)^openshift$`) rather than regex patterns for ID formats. The same validation rules apply — literal patterns must still be anchored and compilable.

### Files in `_deferred/`
If the input includes deferred files (`registry/_deferred/`), validate them but note in the report that deferred files are expected to be incomplete.

### Dual-format files
When both `.json` and `.md` exist for the same namespace, validate each independently. Cross-format consistency (do they agree?) is out of scope for this skill — that's handled by [skills/registry-formalization/](../registry-formalization/).
