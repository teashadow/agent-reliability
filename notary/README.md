# notary — MAD mutation gate
> Threat model: a CaMeL-flavored control ([Debenedetti et al., 2025](https://simonwillison.net/2025/Apr/11/camel/)) — irreversible (consequential) actions require a code-verified signature, not a model's good mood.

Нет подписи — нет мутации. Гейт проверяет подписанное разрешение перед необратимой операцией агента.

## Anti-replay (issue #20, closed 31.08.2026)

Anti-replay is two independent layers:

1. **ts window** — a request older/younger than ±300s is denied (rc=1);
2. **replay journal** — every allowed signature is persisted (JSONL, path via
   `NOTARY_JOURNAL_FILE`, default `~/.local/share/mad/notary/journal.jsonl`,
   entries TTL = the window). The same signed request replayed inside the
   window is **denied rc=1**.

Fail-safe by design: an **unreadable or unwritable journal is rc=2
(indeterminate)**, never allow — freshness that cannot be recorded cannot be
proven. A legitimate re-run after the window simply signs a new request.

## Environment

| var | meaning |
|---|---|
| `NOTARY_KEY_FILE` | HMAC key file (value never printed) |
| `NOTARY_JOURNAL_FILE` | replay journal path (default `~/.local/share/mad/notary/journal.jsonl`) |
