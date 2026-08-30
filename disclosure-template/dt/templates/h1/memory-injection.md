# [{{severity_label}}] {{type_label}} in {{target}}

## Summary
[Persistent memory state can be attacker-influenced and replayed across sessions.]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
Memory Injection

### Root Cause
[Persistent memory is reused without trust partitioning or sanitization]

### Attack Vector
[How attacker gets malicious content stored into memory]

## Steps to Reproduce
1. [Store malicious memory]
2. [Start fresh session]
3. [Observe cross-session influence]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Cross-session compromise, persistence, data leakage]

## Remediation
- [Add scoped memory isolation]
- [Validate or redact unsafe memory content]

## References
- [OWASP LLM Top 10 — memory and context persistence risks]
