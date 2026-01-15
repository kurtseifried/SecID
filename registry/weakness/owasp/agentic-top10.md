---
type: weakness
namespace: owasp
name: agentic-top10
full_name: "OWASP Top 10 for Agentic Applications"
operator: "secid:entity/owasp"

urls:
  website: "https://genai.owasp.org/"
  index: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
  announcement: "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"
  lookup: "https://genai.owasp.org/agentic/{id}/"

id_pattern: "ASI\\d{2}"
versions:
  - "2026"

examples:
  - "secid:weakness/owasp/agentic-top10#ASI01"
  - "secid:weakness/owasp/agentic-top10#ASI06"
  - "secid:weakness/owasp/agentic-top10#ASI10"

status: active
---

# OWASP Top 10 for Agentic Applications

Security risks specific to AI agents - autonomous systems that can plan, act, use tools, and make decisions with limited human oversight. Released December 2025.

## Format

```
secid:weakness/owasp/agentic-top10#ASIXX
secid:weakness/owasp/agentic-top10#ASI01
secid:weakness/owasp/agentic-top10#ASI06
```

## The 10 Risks (2026 Edition)

| ID | Name | Description |
|----|------|-------------|
| ASI01 | Agent Goal Hijack | Attacker alters agent's objectives through malicious content |
| ASI02 | Tool Misuse and Exploitation | Agent uses legitimate tools in unsafe ways |
| ASI03 | Identity and Privilege Abuse | Agent escalates privileges or impersonates |
| ASI04 | Agentic Supply Chain Vulnerabilities | Runtime dependencies (MCP servers, plugins) compromised |
| ASI05 | Unexpected Code Execution | Agent executes unintended code |
| ASI06 | Memory and Context Poisoning | Corrupting agent's persistent memory or context |
| ASI07 | Insecure Inter-Agent Communication | Attacks on agent-to-agent protocols |
| ASI08 | Cascading Failures | Failures propagating through agent chains |
| ASI09 | Human-Agent Trust Exploitation | Social engineering through agent interfaces |
| ASI10 | Rogue Agents | Agents acting outside intended bounds |

## Why Agentic AI Needs Its Own Top 10

Agentic systems introduce unique risks not covered by LLM Top 10:

| Characteristic | Risk Implication |
|----------------|------------------|
| **Autonomy** | Agents act without human approval per action |
| **Tool use** | Agents can execute code, call APIs, modify files |
| **Chaining** | Multiple agents collaborate, amplifying risks |
| **Persistence** | Agents maintain state across sessions |
| **Goal pursuit** | Agents may find unexpected ways to achieve objectives |

## Key Principle: Least Agency

The framework introduces the principle of **least agency**:

> Only grant agents the minimum autonomy required to perform safe, bounded tasks.

## Real-World Incidents

The Top 10 is based on observed incidents:

- Agent-mediated data exfiltration
- Remote code execution via tool misuse
- Memory poisoning attacks
- Supply chain compromise (first malicious MCP server found September 2025)

## Relationship to LLM Top 10

| LLM Top 10 | Agentic Top 10 |
|------------|----------------|
| LLM as component | LLM + tools + autonomy |
| Output risks | Action risks |
| Single-turn focus | Multi-turn, persistent focus |
| Human in loop assumed | Minimal human oversight |

## Supporting Resources

| Resource | Description |
|----------|-------------|
| State of Agentic Security 1.0 | Current landscape analysis |
| Agentic Security Solutions Landscape | Tool comparison |
| Practical Guide to Securing Agentic Applications | Implementation guidance |
| OWASP FinBot CTF | Reference application |

## Notes

- Released December 10, 2025
- Developed by 100+ industry experts
- Critical for MCP, LangChain, AutoGPT, CrewAI security
- Complements LLM Top 10, doesn't replace it
