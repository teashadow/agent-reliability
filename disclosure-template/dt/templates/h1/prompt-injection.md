# [{{severity_label}}] {{type_label}} via {{vector}} in {{target}}

## Summary
[One paragraph: what is the vulnerability, what is possible]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
Prompt Injection — [Direct/Indirect]

### Root Cause
[Where exactly the unsanitized input reaches the LLM context]

### Attack Vector
[How attacker controls the injected content]

## Steps to Reproduce
1. [Prerequisite setup]
2. [Trigger action]
3. [Observe result]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Concrete: data exfiltration / action execution / PII leak / etc.]

## Remediation
- [Specific fix recommendation]
- [Secondary hardening]

## References
- [OWASP LLM Top 10 — LLM01: Prompt Injection]
- [Relevant CVE or writeup if any]
