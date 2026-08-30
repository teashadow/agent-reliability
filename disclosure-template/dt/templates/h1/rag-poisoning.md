# [{{severity_label}}] {{type_label}} in {{target}}

## Summary
[Attacker-controlled knowledge base content poisons retrieval and influences model output.]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
RAG Poisoning

### Root Cause
[Untrusted content enters retrieval corpus without validation]

### Attack Vector
[How attacker uploads or causes indexing of malicious content]

## Steps to Reproduce
1. [Insert malicious document]
2. [Trigger retrieval query]
3. [Observe poisoned answer or instruction following]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Persistent corruption of agent reasoning and unsafe actions]

## Remediation
- [Add source trust scoring and content moderation before indexing]
- [Bind retrieval output to non-instructional context]

## References
- [OWASP LLM Top 10 — LLM04: Data and Model Poisoning]
