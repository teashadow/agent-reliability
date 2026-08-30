# [{{severity_label}}] {{type_label}} in {{target}}

## Summary
[The model routes to the wrong tool or interprets tool metadata ambiguously.]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
Tool Confusion

### Root Cause
[Overlapping tool semantics or insufficient tool-call constraints]

### Attack Vector
[How attacker triggers an unintended tool path]

## Steps to Reproduce
1. [Prepare ambiguous or malicious prompt/tool state]
2. [Trigger tool selection]
3. [Observe wrong tool chosen]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Wrong action execution, secret disclosure, unsafe side effects]

## Remediation
- [Tighten tool schemas and routing rules]
- [Add post-selection validation]

## References
- [Prompt/tool routing security writeups]
