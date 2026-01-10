# Contributing to SecID

Contributions are welcome! SecID is a community project and benefits from diverse input.

## Ways to Contribute

- **Registry additions** - New namespaces, seed data, corrections
- **Documentation** - Improvements, examples, clarifications
- **Spec feedback** - Edge cases, clarifications (spec changes are rare)
- **Research** - Identifying security identifier systems to include

## How to Contribute

1. **Open an issue** - Discuss your idea before starting work
2. **Fork the repository**
3. **Make your changes**
4. **Submit a pull request**

## File Formats

**Registry files** use YAML frontmatter + markdown (Obsidian-compatible):

```markdown
---
type: advisory
namespace: example
common_name: Example Advisory
---

# Content here...
```

**Documentation files** use plain markdown.

See [README.md](README.md#file-format) and [SPEC.md](SPEC.md#72-markdown-body-rich-context) for format details.

## Guidelines

- Follow existing patterns in the registry
- Use percent encoding for special characters in identifiers (see [SPEC.md](SPEC.md#82-percent-encoding))
- Keep commit messages clear and concise
- One logical change per pull request

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

## Questions?

Open a GitHub issue for questions or discussion.
