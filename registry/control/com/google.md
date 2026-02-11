---
type: control
namespace: google.com
full_name: "Google"
operator: "secid:entity/google.com"
website: "https://safety.google"
status: active

sources:
  saif:
    full_name: "Secure AI Framework"
    urls:
      website: "https://safety.google/cybersecurity-advancements/saif"
      blog: "https://blog.google/technology/safety-security/introducing-googles-secure-ai-framework/"
    versions:
      - "1.0"
    examples:
      - "secid:control/google.com/saif#foundation"
      - "secid:control/google.com/saif#detection"

  frontier-safety:
    full_name: "Frontier Safety Framework"
    urls:
      website: "https://deepmind.google/discover/blog/introducing-the-frontier-safety-framework/"
      paper: "https://storage.googleapis.com/deepmind-media/DeepMind.com/Blog/updating-the-frontier-safety-framework/Frontier%20Safety%20Framework%202.0.pdf"
    versions:
      - "2.0"
    examples:
      - "secid:control/google.com/frontier-safety#critical-capability-levels"
      - "secid:control/google.com/frontier-safety#evaluation-protocols"
---

# Google AI Security Controls

Google provides AI security frameworks addressing both enterprise AI deployment (SAIF) and frontier model safety (Frontier Safety Framework).

## Why Google's Frameworks Matter

Google operates AI at massive scale:

- **Deployed AI** - Search, Gmail, Cloud AI services
- **Frontier models** - Gemini, PaLM
- **Security expertise** - Google security team, Project Zero
- **Industry influence** - Frameworks adopted by others

---

## saif

The Secure AI Framework (SAIF) provides a conceptual framework for securing AI systems in enterprise environments.

### Format

```
secid:control/google.com/saif#<element>
```

### SAIF Elements

| Element | Description |
|---------|-------------|
| **Expand security foundations** | Apply existing security practices to AI |
| **Extend detection and response** | Monitor AI-specific threats |
| **Automate defenses** | Use AI to improve security |
| **Harmonize controls** | Consistent security across platforms |
| **Adapt controls for AI** | AI-specific security measures |
| **Contextualize AI risks** | Business context for AI security |

### Core Principles

1. **Build on existing security** - Don't reinvent, extend
2. **AI-specific controls** - Address unique AI risks
3. **Defense in depth** - Multiple layers of protection
4. **Continuous improvement** - Adapt to evolving threats

### Application Areas

| Area | SAIF Guidance |
|------|---------------|
| Model security | Protect model weights, prevent theft |
| Data security | Training data protection |
| Inference security | Prompt injection, output validation |
| Supply chain | Model provenance, dependencies |

### Notes

- Published June 2023
- Conceptual framework, not prescriptive controls
- Aligns with NIST CSF and AI RMF
- Focused on enterprise AI deployment

---

## frontier-safety

Google DeepMind's Frontier Safety Framework defines critical capability levels and safety protocols for advanced AI systems.

### Format

```
secid:control/google.com/frontier-safety#<element>
```

### Critical Capability Levels (CCLs)

Similar to Anthropic's ASL, Google defines capability thresholds:

| Domain | What It Measures |
|--------|------------------|
| Autonomy | Self-directed action capabilities |
| Biosecurity | Potential for biological harm |
| Cybersecurity | Offensive cyber capabilities |
| Machine Learning | Self-improvement capabilities |

### Framework Components

| Component | Purpose |
|-----------|---------|
| **Capability evaluations** | Assess dangerous capabilities |
| **Safety cases** | Document why deployment is safe |
| **If-then commitments** | Predetermined responses to capability levels |
| **Governance** | Oversight and decision-making |

### Evaluation Protocols

The framework specifies:
- Regular capability assessments
- Red teaming requirements
- External audits
- Incident response procedures

### Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| Anthropic ASL | Similar capability-based approach |
| OpenAI Preparedness | Complementary safety framework |
| UK AISI | Evaluation collaboration |

### Notes

- Version 2.0 published 2024
- Applies to Gemini and future models
- Includes public commitments
- Evolves with AI capabilities
