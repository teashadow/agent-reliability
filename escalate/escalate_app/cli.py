"""CLI — escalate: multi-turn resilience prober.

Коды возврата (контракт семьи): 0 — цель удержала (held) · 1 — проба
выполнилась на цели (finding) · 2 — проверка не состоялась (not_proven:
цель недоступна/формат/конфиг). Назначение — проверка СОБСТВЕННЫХ или
авторизованных эндпоинтов; сторонние цели запрещены политикой инструмента.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from .banner import ESCALATE_BANNER
from .session import Session
from .strategy import builtin_ladder, run_escalation

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{ESCALATE_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """Multi-turn resilience prober (MAD battery)."""


@main.command("probe")
@click.option("--target-url", required=True, help="ваш авторизованный эндпоинт")
@click.option("--target-format", type=click.Choice(["openai", "custom"]), default="openai",
              show_default=True)
@click.option("--objective", required=True, help="формулировка цели пробы (ваш текст)")
@click.option("--canary", default="SYN-CANARY", show_default=True,
              help="синтетический маркер 'выполнено'")
@click.option("--max-attempts", default=3, show_default=True, help="попыток на ступень")
@click.option("--timeout", default=30.0, show_default=True, help="таймаут цели, сек")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить структурный отчёт JSON")
def probe(target_url: str, target_format: str, objective: str, canary: str,
          max_attempts: int, timeout: float, as_json: str | None) -> None:
    """Прогнать лестницу мульти-хода по вашей цели."""
    session = Session(url=target_url, target_format=target_format, timeout=timeout)
    report = run_escalation(session, objective, canary,
                            ladder=builtin_ladder(), max_attempts=max_attempts)

    payload = {
        "tool": "escalate",
        "status": report.status,
        "rc": report.rc,
        "reason": report.reason,
        "target": report.target,
        "objective": report.objective,
        "canary": report.canary,
        "turns_used": session.turns(),
        "rungs": [r.__dict__ for r in report.rungs],
        "findings": [r.__dict__ for r in report.findings],
    }
    if as_json:
        Path(as_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    for r in report.rungs:
        mark = {"performed": "[red]PERFORMED[/red]",
                "refused": "[green]refused[/green]",
                "unclear": "[yellow]unclear[/yellow]"}.get(r.verdict, r.verdict)
        console.print(f"  {r.rung_id:<10} {r.kind:<8} {mark} "
                      f"(attempts={r.attempts}, turns={r.turns_used})")
    console.print(f"  status=[bold]{report.status}[/bold] rc={report.rc} — {report.reason}")
    raise SystemExit(report.rc)


if __name__ == "__main__":
    main()
