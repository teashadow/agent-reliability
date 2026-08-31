"""_common — the shared base layer of hostile inputs for the whole battery.

The 10 probes (our standing QA standard, agreed with Nevis 31.08.2026):
health · empty · noise · repeat · flood · injection · secret · unicode ·
badjson · latency.

Аудит-шапка (madd, 31.08.2026):
  Назначение: единый слой злонамеренных входов и тестовых шимов — каждая
    утилита проверяется одними и теми же пробами, копии инъекций не плодятся.
  Вход: ничего (probes — чистые генераторы; injection/secret принимают
    канарейку или берут дефолтную синтетическую).
  Выход: списки строк-нагрузок (probes.py) и программируемые HTTP-шимы
    (shims.py); всё живёт только на 127.0.0.1.
  Рамка авторизации: это тестовая инфраструктура репозитория — шимы слушают
    локально и отвечают только тестам; наружу не стучат.
  НЕ доказывает: стойкость реальных систем (шимы — не цели); пробы — синтетика
    для QA наших детекторов, не арсенал для чужих систем.
"""

from ._probes import (
    PROBE_NAMES,
    probe_badjson,
    probe_empty,
    probe_flood,
    probe_health,
    probe_injection,
    probe_noise,
    probe_repeat,
    probe_secret,
    probe_unicode,
    synthetic_canary,
)
from ._shims import BehaviorShim, LatencyShim

PROBES = {
    "health": probe_health,
    "empty": probe_empty,
    "noise": probe_noise,
    "repeat": probe_repeat,
    "flood": probe_flood,
    "injection": probe_injection,
    "secret": probe_secret,
    "unicode": probe_unicode,
    "badjson": probe_badjson,
}

__all__ = [
    "PROBES", "PROBE_NAMES", "synthetic_canary",
    "probe_badjson", "probe_empty", "probe_flood", "probe_health",
    "probe_injection", "probe_noise", "probe_repeat", "probe_secret",
    "probe_unicode",
    "BehaviorShim", "LatencyShim",
]
