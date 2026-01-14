---
type: weakness
namespace: owasp
name: agentic-top10
full_name: "OWASP Agentic AI Top 10"
operator: "secid:entity/owasp"

urls:
  website: "https://owasp.org/www-project-agentic-ai-threats-and-mitigations/"
  lookup: "https://owasp.org/www-project-agentic-ai-threats-and-mitigations/"

id_pattern: "AGT\\d{2}"

examples:
  - "secid:weakness/owasp/agentic-top10#AGT01"
  - "secid:weakness/owasp/agentic-top10#AGT05"

status: active
---

# OWASP Agentic AI Top 10

Security risks specific to AI agents - autonomous systems that can take actions, use tools, and operate with minimal human oversight.

## Format

```
secid:weakness/owasp/agentic-top10#ITEM
secid:weakness/owasp/agentic-top10#AGT01
```

## Why Agentic AI Needs Its Own Top 10

Agentic AI systems introduce unique risks:

- **Autonomy** - Agents act without human approval
- **Tool use** - Agents can execute code, call APIs, access files
- **Chaining** - Multiple agents collaborate, amplifying risks
- **Persistence** - Agents may maintain state across sessions
- **Goal pursuit** - Agents may find unexpected ways to achieve objectives

## Key Risk Categories

| Risk | Description |
|------|-------------|
| Excessive Agency | Agent has more permissions than needed |
| Tool Abuse | Agent misuses available tools |
| Goal Misalignment | Agent pursues objectives in harmful ways |
| Prompt Injection | Attacks that hijack agent behavior |
| Memory Poisoning | Corrupting agent's persistent memory |
| Privilege Escalation | Agent gains unauthorized capabilities |
| Multi-Agent Attacks | Exploiting agent-to-agent communication |

## Relationship to LLM Top 10

| LLM Top 10 | Agentic Top 10 |
|------------|----------------|
| LLM as component | LLM + tools + autonomy |
| Output risks | Action risks |
| Single-turn focus | Multi-turn, persistent focus |
| Human in loop assumed | Minimal human oversight |

## Notes

- Emerging area as AI agents become more capable
- Critical for MCP, LangChain, AutoGPT, etc.
- Overlaps with but extends LLM Top 10
