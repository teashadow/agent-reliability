"""CLI — spike: single-shot prompt-injection battery.

Коды возврата (контракт семьи): 0 — цель удержала · 1 — техника выполнилась
(finding) · 2 — проверка не состоялась. Только авторизованные/свои цели.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from .banner import SPIKE_BANNER
from .tester import run

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{SPIKE_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """Single-shot prompt-injection battery (MAD battery)."""


@main.command("run")
@click.option("--url", required=True, help="ваш авторизованный LLM-эндпоинт")
@click.option("--format", "fmt", type=click.Choice(["openai", "custom", "get"]),
              default="custom", show_default=True)
@click.option("--body", default=None, help='шаблон тела для custom: {"message": "PAYLOAD"}')
@click.option("--key", default=None, help="Bearer-ключ (не попадает в отчёт)")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить структурный отчёт JSON")
def run_cmd(url: str, fmt: str, body: str | None, key: str | None,
            as_json: str | None) -> None:
    """Прогнать всю батарею по одной цели."""
    report = run(url, fmt=fmt, body=body, key=key)
    if as_json:
        Path(as_json).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    for f in report["findings"]:
        if f["verdict"] == "performed":
            console.print(f"  [red]{f['group']}:{f['category']}[/red] performed — {f['why']}")
        else:
            console.print(f"  [dim]{f['group']}:{f['category']} not_checked — {f['why']}[/dim]")
    color = {"held": "green", "finding": "red", "not_proven": "yellow"}[report["status"]]
    console.print(f"  status=[bold {color}]{report['status']}[/] rc={report['rc']} "
                  f"— {report['reason']}")
    raise SystemExit(report["rc"])


if __name__ == "__main__":
    main()
