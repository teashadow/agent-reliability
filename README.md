# MADD · Agent Reliability & Security Tooling

**We break agents so they don't break in production.**

> Landing in progress. The full README lands here from the project's own hand;
> utilities arrive one PR at a time, each with a test that proves it bites.

## Authorization scope — read before anything else

Every tool in this repository is built for **authorized** work only:

- arenas that explicitly invite adversarial testing of their systems under their rules
  (Gray Swan, HackerOne, HackAPrompt, Immunefi and the like),
- **your own** systems and agents,
- bug-bounty targets **within their stated scope**.

Anything else is outside the design intent of this repository. The boundary is the
authorization, not the capability — the tools are sharp on purpose.

## Threat model — the language the battery speaks

The battery is organized around the two load-bearing ideas of the 2025–2026
prompt-injection literature:

- **The lethal trifecta** ([Willison, June 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)):
  an agent that combines *access to private data* (leg 1), *exposure to untrusted
  content* (leg 2) and *the ability to communicate externally* (leg 3) can be tricked
  into exfiltrating that data — and guardrails do not reliably close this.
- **CaMeL** ([Debenedetti et al., Google DeepMind, 2025](https://simonwillison.net/2025/Apr/11/camel/)):
  don't trust the model to tell instructions from data — enforce control- and
  data-flow policy in code around the model.

The battery's contract follows the CaMeL instinct: **verdicts are set by code,
never by a model reading a model.** Utilities address the trifecta legs as follows:

| utility | trifecta leg / control addressed |
|---|---|
| [banshee](banshee/) | surface recon of authorized targets — leg 2 entry points, mapped first |
| [spike](spike/) | leg 2 → output channel, single-shot (execution & disclosure) |
| [escalate](escalate/) | leg 2 across a conversation (multi-turn depth) |
| [warden](warden/) | runtime watcher: legs 1+2 meeting in the agent's event stream |
| [notary](notary/) | CaMeL-flavored control: irreversible mutation requires a code-verified signature |
| [arbiter](arbiter/) | dual-LLM pattern: model proposes, code validates against a real allow-list |
| [finding-organizer](finding-organizer/) | shared findings store feeding the above |
| [disclosure-template](disclosure-template/) | responsible disclosure of what the battery found |
