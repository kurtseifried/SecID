---
type: control
namespace: metr.org
full_name: "METR (Model Evaluation and Threat Research)"
operator: "secid:entity/metr.org"
website: "https://metr.org"
status: active

sources:
  task-standard:
    full_name: "METR Task Standard"
    urls:
      website: "https://metr.org/blog/2024-08-06-task-standard/"
      github: "https://github.com/METR/task-standard"
    versions:
      - "2024"
    examples:
      - "secid:control/metr.org/task-standard"

  evaluations:
    full_name: "METR Evaluations"
    urls:
      website: "https://metr.org/work/"
      autonomy: "https://metr.org/blog/2024-03-13-autonomy-evaluation-resources/"
    examples:
      - "secid:control/metr.org/evaluations#autonomy"
      - "secid:control/metr.org/evaluations#capability"
---

# METR Evaluations

METR (Model Evaluation and Threat Research) develops rigorous evaluations for dangerous AI capabilities, particularly autonomous AI agents.

## Why METR Matters

Independent capability evaluation:

- **Frontier focus** - Tests most advanced models
- **Autonomy emphasis** - Agent capability evaluation
- **Independence** - Third-party assessments
- **Standardization** - Task Standard for reproducibility

---

## task-standard

The METR Task Standard provides a format for defining AI agent evaluation tasks.

### Format

```
secid:control/metr.org/task-standard
```

### What Task Standard Prescribes

Standardized format for:
- Defining agent tasks
- Specifying success criteria
- Creating reproducible evaluations
- Measuring agent capabilities

### Task Components

| Component | Description |
|-----------|-------------|
| **Task definition** | What the agent must accomplish |
| **Environment** | Sandbox, tools, resources available |
| **Instructions** | What agent is told |
| **Success criteria** | How completion is measured |
| **Scoring** | Grading rubric |

### Environment Specification

| Element | Description |
|---------|-------------|
| Docker container | Isolated execution environment |
| Available tools | CLI, browser, APIs |
| Time limits | Maximum task duration |
| Resource limits | Compute, memory, network |

### Use Cases

| Use | Description |
|-----|-------------|
| Pre-deployment | Test before release |
| Capability tracking | Monitor improvement |
| Red teaming | Find dangerous capabilities |
| Comparison | Cross-model evaluation |

### Notes

- Open specification
- GitHub repository available
- Used by AI labs
- Enables reproducible research

---

## evaluations

METR conducts evaluations of AI agent capabilities, especially autonomous operation.

### Format

```
secid:control/metr.org/evaluations#<type>
```

### Evaluation Types

| Type | What It Tests |
|------|---------------|
| **Autonomy** | Self-directed task completion |
| **Capability** | Specific dangerous abilities |
| **R&D** | AI research and development capability |
| **Cyber** | Offensive cyber operations |

### Autonomy Evaluation

Tests whether AI can:
- Break down complex goals
- Execute multi-step plans
- Use tools effectively
- Recover from errors
- Operate without human guidance

### Capability Domains

| Domain | Examples |
|--------|----------|
| Software engineering | Writing, debugging code |
| Research | Literature review, experimentation |
| Cyber operations | Vulnerability discovery, exploitation |
| Persuasion | Social engineering capability |
| Self-improvement | Ability to enhance own capabilities |

### Evaluation Process

1. Define tasks per Task Standard
2. Run AI agent on tasks
3. Measure success rate
4. Analyze failure modes
5. Report capabilities

### Clients

METR has evaluated models for:
- Anthropic
- OpenAI
- Google DeepMind
- UK AI Safety Institute

### Public Resources

| Resource | Description |
|----------|-------------|
| Task Standard | Open specification |
| Example tasks | Reference implementations |
| Evaluation reports | Published findings |

### Notes

- Founded by former OpenAI/Anthropic staff
- Focus on autonomous agents
- Informs deployment decisions
- Supports AI safety institutes
