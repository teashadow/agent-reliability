# [{{severity_label}}] {{type_label}} via {{vector}} in {{target}}

## Summary
[One paragraph: what is the vulnerability, what is possible]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Priority:** [P1/P2/P3/P4/P5]
- **Bug URL:** {{bug_url}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
{{type_label}}

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
[Concrete impact]

## Remediation
- [Specific fix recommendation]
- [Secondary hardening]
