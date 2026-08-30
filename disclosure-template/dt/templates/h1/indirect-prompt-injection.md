# [{{severity_label}}] {{type_label}} via external content in {{target}}

## Summary
[Indirect prompt injection through attacker-controlled content rendered into the model context.]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
Prompt Injection — Indirect

### Root Cause
[Where external content is ingested without trust separation]

### Attack Vector
[How a document, page, or remote source reaches the LLM]

## Steps to Reproduce
1. [Prepare malicious external content]
2. [Make target ingest or retrieve it]
3. [Observe model following attacker instructions]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Cross-source instruction override, data exfiltration, action hijack]

## Remediation
- [Add trust boundaries between retrieved content and system instructions]
- [Filter or sandbox untrusted content]

## References
- [OWASP LLM Top 10 — LLM01: Prompt Injection]
