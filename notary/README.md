# notary — MAD mutation gate
> Threat model: a CaMeL-flavored control ([Debenedetti et al., 2025](https://simonwillison.net/2025/Apr/11/camel/)) — irreversible (consequential) actions require a code-verified signature, not a model's good mood.

Нет подписи — нет мутации. Гейт проверяет подписанное разрешение перед необратимой операцией агента.
