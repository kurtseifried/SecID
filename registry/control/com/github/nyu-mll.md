---
type: control
namespace: github.com/nyu-mll
full_name: "Bias Benchmarks"
operator: "secid:entity/various"
website: "https://github.com/nyu-mll/BBQ"
status: active

sources:
  bbq:
    full_name: "Bias Benchmark for QA"
    urls:
      website: "https://github.com/nyu-mll/BBQ"
      paper: "https://arxiv.org/abs/2110.08193"
    versions:
      - "2022"
    examples:
      - "secid:control/github.com/nyu-mll/bbq#age"
      - "secid:control/github.com/nyu-mll/bbq#gender"

  winobias:
    full_name: "WinoBias"
    urls:
      website: "https://github.com/uclanlp/corefBias"
      paper: "https://arxiv.org/abs/1804.06876"
    examples:
      - "secid:control/github.com/nyu-mll/winobias"

  stereoset:
    full_name: "StereoSet"
    urls:
      website: "https://github.com/moinnadeem/StereoSet"
      paper: "https://arxiv.org/abs/2004.09456"
    examples:
      - "secid:control/github.com/nyu-mll/stereoset#gender"
      - "secid:control/github.com/nyu-mll/stereoset#race"

  crowspairs:
    full_name: "CrowS-Pairs"
    urls:
      website: "https://github.com/nyu-mll/crows-pairs"
      paper: "https://arxiv.org/abs/2010.00133"
    examples:
      - "secid:control/github.com/nyu-mll/crowspairs"
---

# Bias Benchmarks

A collection of benchmarks prescribing how to test for social biases in language models.

## Why Bias Benchmarks Matter

Systematic bias evaluation:

- **Standardized** - Consistent methodology across models
- **Comprehensive** - Multiple bias dimensions
- **Actionable** - Identifies specific bias types
- **Research foundation** - Widely cited and used

---

## bbq

BBQ (Bias Benchmark for QA) tests social biases in question answering across 9 protected categories.

### Format

```
secid:control/github.com/nyu-mll/bbq#<category>
```

### Nine Bias Categories

| Category | What It Tests |
|----------|---------------|
| **Age** | Ageism, generational stereotypes |
| **Disability** | Ableism, capability assumptions |
| **Gender** | Sexism, gender role stereotypes |
| **Nationality** | National origin bias |
| **Physical appearance** | Lookism, body stereotypes |
| **Race/ethnicity** | Racial and ethnic bias |
| **Religion** | Religious stereotypes |
| **Socioeconomic status** | Class-based bias |
| **Sexual orientation** | LGBTQ+ stereotypes |

### Test Structure

| Component | Description |
|-----------|-------------|
| Context | Ambiguous scenario |
| Question | Query about participants |
| Answers | Including "unknown" option |

### Metrics

| Metric | Description |
|--------|-------------|
| Bias score | Preference for stereotyped answers |
| Accuracy | Correct "unknown" when ambiguous |

### Notes

- 58,492 examples
- Tests both accuracy and bias
- Ambiguous and disambiguated versions
- Google research collaboration

---

## winobias

WinoBias tests gender bias in coreference resolution systems.

### Format

```
secid:control/github.com/nyu-mll/winobias
```

### What It Prescribes

Test your model for:
- Gender stereotypes in occupation references
- Bias in pronoun resolution
- Pro-stereotype vs anti-stereotype performance

### Test Structure

| Type | Example |
|------|---------|
| Pro-stereotype | "The nurse... she" (matches stereotype) |
| Anti-stereotype | "The nurse... he" (against stereotype) |

### Occupations Tested

40 occupations with gender statistics:
- Stereotypically male (mechanic, CEO)
- Stereotypically female (nurse, secretary)
- Gender-balanced comparisons

### Metrics

| Metric | Description |
|--------|-------------|
| TPR gap | Difference in performance by gender |
| Stereotype preference | Bias toward stereotyped resolution |

### Notes

- Winograd-schema inspired
- Tests coreference systems
- Reveals occupation-gender bias
- Widely used baseline

---

## stereoset

StereoSet measures stereotypical bias across four domains.

### Format

```
secid:control/github.com/nyu-mll/stereoset#<domain>
```

### Four Bias Domains

| Domain | What It Tests |
|--------|---------------|
| **Gender** | Sex-based stereotypes |
| **Race** | Racial/ethnic stereotypes |
| **Religion** | Faith-based stereotypes |
| **Profession** | Occupation stereotypes |

### Test Types

| Type | Description |
|------|-------------|
| Intrasentence | Fill-in-the-blank bias |
| Intersentence | Sentence continuation bias |

### Metrics

| Metric | Description |
|--------|-------------|
| Language Model Score (lms) | Model's language quality |
| Stereotype Score (ss) | Preference for stereotypes |
| ICAT | Idealized CAT (combines both) |

### Notes

- 17,000 test instances
- Measures stereotype preference
- Balances language quality and bias
- Targets specific demographic groups

---

## crowspairs

CrowS-Pairs evaluates stereotypes through minimal pair comparisons.

### Format

```
secid:control/github.com/nyu-mll/crowspairs
```

### Nine Bias Types

| Type | Description |
|------|-------------|
| Race/color | Racial stereotypes |
| Gender | Sex-based stereotypes |
| Sexual orientation | LGBTQ+ stereotypes |
| Religion | Faith-based stereotypes |
| Age | Ageism |
| Nationality | National origin bias |
| Disability | Ableism |
| Physical appearance | Lookism |
| Socioeconomic status | Class bias |

### Methodology

Minimal pairs comparing:
- Stereotyping sentence
- Anti-stereotyping sentence
- Measures which model prefers

### Metrics

| Metric | Description |
|--------|-------------|
| Stereotype score | % preference for stereotype |
| 50% = unbiased | Equal preference |

### Notes

- 1,508 sentence pairs
- Crowdsourced examples
- Covers intersectional biases
- Direct comparison approach
