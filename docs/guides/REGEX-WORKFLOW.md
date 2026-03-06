# How to Write and Test Regex Patterns for match_nodes

## Security Status
**Status: Active guidance (not a stub).**

This guide defines how SecID handles regex safety for registry `match_nodes`.

## Threat Model
SecID-Service executes registry patterns against user-controlled identifiers at runtime. A pathological pattern could cause catastrophic backtracking (ReDoS) and CPU spikes.

## Accepted Risk Statement
SecID **accepts** runtime regex execution risk because flexible identifier support depends on source-specific patterns. Risk is controlled at registry authoring/review time, not eliminated at runtime.

## Required Controls Before Merge
For every new or changed pattern:

1. Anchor patterns with `^` and `$`.
2. Avoid backtracking-prone constructs: nested quantifiers (`(a+)+`), ambiguous overlap (`(a|aa)+`), wide `.*` inside repeated groups.
3. Validate against real positive and negative examples from the source.
4. Run a ReDoS check (for example `recheck` or equivalent analyzer) and capture the result in PR notes.
5. Confirm cross-runtime compatibility (JavaScript, Python, Go, Rust expectations in this repo).
6. Include explicit reviewer sign-off that regex safety was checked.

## Implementation Reality (Current)
These controls are currently enforced through contributor workflow and review discipline, including AI-assisted analysis, not through a hard CI gate.

## PR Checklist Snippet
Add this to PR descriptions for regex changes:

- `ReDoS reviewed:` Yes/No
- `Analyzer/tool used:` ...
- `Worst-case behavior checked:` ...
- `Example set added/updated:` ...

## Residual Risk and Escalation
Residual risk remains if a bad pattern passes review. If production latency or CPU behavior indicates regex abuse, rollback the registry change and re-review affected patterns before re-deploy.
