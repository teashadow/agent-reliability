# [{{severity_label}}] {{type_label}} in {{target}}

## Summary
[Injection through MCP or SSE-delivered tool output that is trusted by the model.]

## Platform
- **Platform:** {{platform_name}}
- **Program:** {{program}}
- **Severity:** {{severity}}
- **CVSS:** {{cvss}}
- **CWE:** {{cwe}}

## Vulnerability Details
### Type
MCP / SSE Injection

### Root Cause
[Tool output is treated as trusted instructions instead of data]

### Attack Vector
[How attacker controls MCP result or streamed event payload]

## Steps to Reproduce
1. [Trigger tool/event path]
2. [Inject crafted SSE or MCP output]
3. [Observe model reinterpret payload as instructions]

## Proof of Concept
```
{{payload}}
```

**Response:**
```
{{response}}
```

## Impact
[Unauthorized action routing, data disclosure, downstream compromise]

## Remediation
- [Separate tool data from instruction channels]
- [Enforce schema validation and neutralization]

## References
- [Model Context Protocol security discussions]
