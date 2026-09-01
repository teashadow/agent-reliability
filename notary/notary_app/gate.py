"""notary gate — проверка подписанного разрешения на необратимую мутацию.

Контракт запроса (request.json):
    {action, target, scope, ts, sig}

    sig = HMAC-SHA256 (hex) над канонической строкой `action|target|scope|ts`
    ключом, лежащим в файле (путь — в env NOTARY_KEY_FILE). Значение ключа
    НИКОГДА не печатается.

Три проверки, все обязаны пройти для allow:
    1. подпись совпадает (иначе запрос подделан/повреждён);
    2. action входит в разрешённый scope (список действий или wildcard "*");
    3. ts в окне ±300 с от текущего времени (антиреплей);
    4. sig не встречался ранее (журнал увиденных подписей — закрытие реплея
       внутри окна: тот же запрос второй раз = DENY rc=1).

Коды возврата (fail-safe: неизвестное = отказ):
    ALLOW         → rc 0   всё сошлось
    DENY          → rc 1   проверка прошла и дала «нет» (подпись/scope/replay)
    INDETERMINATE → rc 2   проверка НЕ СОСТОЯЛАСЬ (нет ключа/битый JSON/нет поля/
                           журнал реплея недоступен — не allow, пока свежесть не доказана)

🔴 Различение rc=1 и rc=2 несущее: rc=2 опаснее, потому что похоже на rc=1.

Аудит-шапка (madd, 31.08.2026):
  Назначение: гейт подписанного разрешения на необратимую мутацию —
    верификация HMAC-подписи запроса ДО того, как мутация исполнена.
  Вход: request.json {action, target, scope, ts, sig}; ключ HMAC —
    в файле по env NOTARY_KEY_FILE (не печатается); журнал реплея —
    по env NOTARY_JOURNAL_FILE (по умолчанию ~/.local/share/mad/notary/journal.jsonl).
  Выход: allow / deny / indeterminate, rc 0 / 1 / 2 (fail-safe:
    неизвестное = отказ); вердикт ставит КОД, ноль обращений к LLM.
  Рамка авторизации: гейт не ВЫДАЁТ права, а проверяет подпись держателя
    ключа; применять на системах, которыми владеешь или работаешь по договору.
  НЕ доказывает: стойкость ключа и хоста (укравший ключ/лог подписывает сам),
    корректность scope-списков; антиреплей = окно ts ±300 с + журнал увиденных
    подписей (TTL = окно); запись, виденная один раз, повторно не пройдёт —
    но легитимный повторный прогон должен подписать запрос заново.
  Egress: ноль — гейт читает файлы запроса/ключа/журнала на своём диске и
    ничего не отправляет.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

# Классы вердикта
ALLOW = "ALLOW"
DENY = "DENY"
INDETERMINATE = "INDETERMINATE"

_RC = {ALLOW: 0, DENY: 1, INDETERMINATE: 2}

# Окно антиреплея, секунды
TS_WINDOW = 300

# Журнал увиденных подписей (антиреплей внутри окна). TTL записей = TS_WINDOW:
# запросы вне окна отсекаются проверкой ts, поэтому записи старше окна мертвы.
DEFAULT_JOURNAL = Path.home() / ".local" / "share" / "mad" / "notary" / "journal.jsonl"

REQUIRED_FIELDS = ("action", "target", "scope", "ts", "sig")


@dataclass
class Verdict:
    verdict: str
    reason: str
    action: str | None = None
    target: str | None = None
    checks: dict = field(default_factory=dict)

    @property
    def rc(self) -> int:
        return _RC[self.verdict]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "rc": self.rc,
            "reason": self.reason,
            "action": self.action,
            "target": self.target,
            "checks": self.checks,
            "not_proven": (
                "Гейт проверяет ТОЛЬКО совпадение подписи, вхождение action в "
                "подписанный scope, свежесть ts и неповторяемость подписи по "
                "журналу реплея (TTL = окно). Он НЕ доказывает, что действие "
                "безопасно, что ключ не утёк (укравший ключ подписывает и "
                "новые запросы), что подписант имел право подписывать, "
                "и что target действительно тот, за кого себя выдаёт."
            ),
        }


def canonical_scope(scope) -> str:
    """Детерминированная сериализация scope для подписи.

    И подписант, и проверяющий обязаны звать ЭТУ функцию — иначе разойдутся
    байты сообщения и подпись не сойдётся при верном ключе.
    """
    if isinstance(scope, str):
        return scope
    if isinstance(scope, (list, tuple)):
        return json.dumps(sorted(scope), ensure_ascii=False, separators=(",", ":"))
    # прочее (dict/число) — стабильно, но нетипично
    return json.dumps(scope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def signing_string(action: str, target: str, scope, ts) -> str:
    """Каноническая строка, над которой берётся HMAC."""
    return f"{action}|{target}|{canonical_scope(scope)}|{ts}"


def compute_sig(key: bytes, action: str, target: str, scope, ts) -> str:
    """HMAC-SHA256 в hex. Общая точка для подписанта и проверяющего."""
    msg = signing_string(action, target, scope, ts).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _load_key() -> bytes | None:
    """Прочитать ключ из файла (путь в env NOTARY_KEY_FILE). Значение не печатать."""
    path = os.environ.get("NOTARY_KEY_FILE")
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    data = p.read_bytes().strip()
    if not data:
        return None
    return data


def _action_in_scope(action: str, scope) -> bool:
    if isinstance(scope, str):
        return scope == "*"
    if isinstance(scope, (list, tuple)):
        if "*" in scope:
            return True
        return action in scope
    return False


# ── журнал увиденных подписей (антиреплей внутри окна) ────────────────────────

def _journal_path() -> Path:
    return Path(os.environ.get("NOTARY_JOURNAL_FILE") or DEFAULT_JOURNAL)


def _seen_recently(journal: Path, sig: str, now: float) -> tuple[bool | None, set[str]]:
    """Прочитать журнал под локом. True/False — виден ли sig среди свежих;
    None — журнал недоступен (битый JSON/нет прав/нет файла-каталога — но
    отсутствующий файл = пустой журнал, это норма)."""
    if not journal.is_file():
        return False, set()
    try:
        with journal.open("r+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fresh: set[str] = set()
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if now - float(rec["seen"]) <= TS_WINDOW:
                        fresh.add(rec["sig"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue  # битую строку не верим и не расширяем на неё вывод
            return (sig in fresh), fresh
    except (OSError, UnicodeDecodeError):
        # нет прав/каталог не тот/не текст — журнал не доверенный: свежесть
        # не может быть доказана → вызывающий обязан дать indeterminate
        return None, set()


def _record_sig(journal: Path, sig: str, ts: float, now: float) -> bool:
    """Дописать sig в журнал. False = запись не удалась (fail-safe → не allow)."""
    try:
        journal.parent.mkdir(parents=True, exist_ok=True)
        with journal.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps({"sig": sig, "ts": ts, "seen": now},
                                ensure_ascii=False) + "\n")
        return True
    except (OSError, TypeError, ValueError):
        return False


def evaluate(request: dict, *, now: float | None = None) -> Verdict:
    """Разобрать уже-распарсенный запрос и вынести вердикт.

    now — для тестируемости; по умолчанию системное время.
    """
    if now is None:
        now = time.time()

    # (0) структура запроса — нет поля → не состоялась (rc=2)
    if not isinstance(request, dict):
        return Verdict(INDETERMINATE, "запрос не является объектом JSON")
    missing = [f for f in REQUIRED_FIELDS if f not in request]
    if missing:
        return Verdict(
            INDETERMINATE,
            f"в запросе нет обязательных полей: {', '.join(missing)}",
        )

    action = request["action"]
    target = request["target"]
    scope = request["scope"]
    ts = request["ts"]
    sig = request["sig"]

    if not isinstance(sig, str) or not sig:
        return Verdict(INDETERMINATE, "поле sig пустое или не строка",
                       action=str(action), target=str(target))
    try:
        ts_num = float(ts)
    except (TypeError, ValueError):
        return Verdict(INDETERMINATE, "поле ts не является числом",
                       action=str(action), target=str(target))

    # ключ — нет ключа → не состоялась (rc=2)
    key = _load_key()
    if key is None:
        return Verdict(
            INDETERMINATE,
            "ключ недоступен (env NOTARY_KEY_FILE не задан / файл пуст / не найден)",
            action=str(action), target=str(target),
        )

    checks: dict = {}

    # (1) подпись — первой: scope и ts подписаны, без ключа их не подделать
    expected = compute_sig(key, action, target, scope, ts)
    sig_ok = hmac.compare_digest(expected, sig)
    checks["signature"] = sig_ok
    if not sig_ok:
        return Verdict(DENY, "подпись не совпадает",
                       action=str(action), target=str(target), checks=checks)

    # (2) вхождение action в подписанный scope
    scope_ok = _action_in_scope(action, scope)
    checks["scope"] = scope_ok
    if not scope_ok:
        return Verdict(DENY, f"action '{action}' вне разрешённого scope",
                       action=str(action), target=str(target), checks=checks)

    # (3) окно антиреплея ±TS_WINDOW
    age = now - ts_num
    ts_ok = abs(age) <= TS_WINDOW
    checks["ts_window"] = ts_ok
    checks["ts_age_seconds"] = round(age, 3)
    if not ts_ok:
        return Verdict(
            DENY,
            f"ts вне окна ±{TS_WINDOW}с (возраст {age:.0f}с) — антиреплей",
            action=str(action), target=str(target), checks=checks,
        )

    # (4) журнал увиденных подписей — реплей внутри окна не должен пройти
    journal = _journal_path()
    seen, _fresh = _seen_recently(journal, sig, now)
    checks["replay_journal"] = "readable"
    if seen is None:
        checks["replay_journal"] = "unreadable"
        return Verdict(
            INDETERMINATE,
            "журнал антиреплея недоступен — свежесть не может быть доказана, "
            "allow невозможен (fail-safe)",
            action=str(action), target=str(target), checks=checks,
        )
    if seen:
        return Verdict(
            DENY,
            "повтор уже виденной подписи — реплей внутри окна",
            action=str(action), target=str(target), checks=checks,
        )
    if not _record_sig(journal, sig, ts_num, now):
        checks["replay_journal"] = "unwritable"
        return Verdict(
            INDETERMINATE,
            "запись в журнал реплея не удалась — allow невозможен (fail-safe)",
            action=str(action), target=str(target), checks=checks,
        )

    return Verdict(ALLOW, "подпись верна, action в scope, ts свеж, реплея нет",
                   action=str(action), target=str(target), checks=checks)


def check_file(path: str, *, now: float | None = None) -> Verdict:
    """Прочитать request.json и вынести вердикт. Битый JSON → rc=2."""
    p = Path(path)
    if not p.is_file():
        return Verdict(INDETERMINATE, f"файл запроса не найден: {path}")
    try:
        raw = p.read_text(encoding="utf-8")
        request = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        return Verdict(INDETERMINATE, f"запрос не читается как JSON: {e}")
    return evaluate(request, now=now)
