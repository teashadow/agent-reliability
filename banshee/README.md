# banshee — attack-surface recon pipeline (authorized targets only)
> Threat model: map the exposed surface of authorized targets first — know the entry points of leg 2 of the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) before probing them.

Orchestrates the classic recon chain — **subfinder → httpx → nuclei → Shodan
enrichment** — behind a hard authorization gate, and reports in the family
verdict contract (JSON + exit code, no model in the decision).

## The gate bites first

`banshee run TARGET` **refuses to scan** unless a scope program is given and
`periscope` confirms the target is in it:

- no `--program` → **DENIED** (fail-safe),
- periscope unreachable or silent → **DENIED** (fail-safe),
- target out of program scope → **DENIED**,
- anything unknown → **DENIED**.

Silence is never consent. Out of the box, with no programs configured, the
tool scans nothing — by design.

```bash
banshee gate demo.example.com demo-program   # check the gate without scanning
banshee run  demo.example.com --program demo-program
banshee verdict demo.example.com             # family verdict: JSON + rc
```

## Family verdict contract

Exit codes and JSON follow the MADD convention — a refusal to decide is never
dressed as a decision:

- `0 ПРОШЁЛ` — live surface mapped, no probe findings;
- `1 ПРОВАЛ` — probe findings on the surface (nuclei hits);
- `2 НЕ ПРОВЕРЕНО` — the check did not happen (no run / incomplete artifacts).

Every verdict carries `not_proven`: recon maps the surface — it does not prove
exploitability, target safety, or coverage completeness.

## Authorization scope

Built for **authorized** work only: arenas that invite adversarial testing
under their rules, your own systems, bug-bounty targets within their stated
scope. Unauthenticated mass scanning of other people's infrastructure is
outside the design intent — the gate exists to make that non-optional.
