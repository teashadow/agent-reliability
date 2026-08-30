"""Static catalog data for inkwell."""

from __future__ import annotations

PLATFORMS = ("h1", "bugcrowd", "intigriti")

VULN_TYPES = (
    "prompt-injection",
    "indirect-prompt-injection",
    "mcp-sse-injection",
    "rag-poisoning",
    "excessive-agency",
    "memory-injection",
    "tool-confusion",
    "jailbreak-persistence",
)

SEVERITY_CWE = {
    "prompt-injection": "CWE-1357 (Reliance on Insufficiently Trustworthy Component)",
    "indirect-prompt-injection": "CWE-74 (Injection)",
    "mcp-sse-injection": "CWE-441 (Unintended Proxy or Intermediary)",
    "rag-poisoning": "CWE-502 (Deserialization of Untrusted Data)",
    "excessive-agency": "CWE-250 (Execution with Unnecessary Privileges)",
    "memory-injection": "CWE-359 (Exposure of Private Personal Information)",
    "tool-confusion": "CWE-436 (Interpretation Conflict)",
    "jailbreak-persistence": "CWE-693 (Protection Mechanism Failure)",
}
