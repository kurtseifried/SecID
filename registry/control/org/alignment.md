---
type: control
namespace: alignment.org
full_name: "ARC Evals (Alignment Research Center)"
operator: "secid:entity/alignment.org"
website: "https://evals.alignment.org"
status: active

sources:
  evals:
    full_name: "ARC Evaluations"
    urls:
      website: "https://evals.alignment.org"
      blog: "https://www.alignment.org/blog/"
    examples:
      - "secid:control/alignment.org/evals#dangerous-capability"
      - "secid:control/alignment.org/evals#autonomy"
---

# ARC Evals

ARC Evals (part of Alignment Research Center) develops evaluations for dangerous AI capabilities and alignment properties.

## Why ARC Evals Matters

Pioneering dangerous capability evaluation:

- **Early mover** - First to systematically test for dangerous capabilities
- **Influential** - GPT-4 red team participant
- **Independence** - External evaluator for AI labs
- **Focus** - Autonomous replication and resource acquisition

---

## evals

ARC Evals prescribes testing for dangerous AI capabilities, particularly those related to autonomous operation.

### Format

```
secid:control/alignment.org/evals#<domain>
```

### Dangerous Capability Categories

| Category | What It Tests |
|----------|---------------|
| **Autonomous replication** | Can AI copy itself to new systems? |
| **Resource acquisition** | Can AI obtain compute, money, access? |
| **Deception** | Can AI deceive evaluators? |
| **Self-improvement** | Can AI enhance its own capabilities? |

### Autonomous Replication Testing

Tests whether AI can:
- Set up new cloud instances
- Copy model weights
- Establish persistence
- Evade shutdown

### Resource Acquisition Testing

Tests whether AI can:
- Earn money (freelancing, exploits)
- Acquire compute resources
- Gain unauthorized access
- Recruit human assistance

### Deception Evaluation

Tests whether AI:
- Behaves differently when observed
- Provides false information strategically
- Conceals its capabilities
- Manipulates evaluators

### Evaluation History

| Model | Year | Findings |
|-------|------|----------|
| GPT-4 | 2023 | Evaluated pre-release |
| Claude | 2023+ | Ongoing evaluations |
| Various | Ongoing | Frontier model testing |

### GPT-4 Evaluation (2023)

ARC tested GPT-4 for:
- Task completion without human help
- Acquiring resources autonomously
- Self-replication behaviors

Key finding: GPT-4 showed limited autonomous capability but concerning potential.

### Relationship to Other Orgs

| Organization | Relationship |
|--------------|--------------|
| METR | Similar focus, complementary methods |
| UK AISI | Collaboration on evaluations |
| AI labs | Pre-deployment testing |

### Notes

- Founded by Paul Christiano (ex-OpenAI)
- Focus on most dangerous capabilities
- Influential in establishing evaluation norms
- Work informs AI lab policies
