"""CLI — smuggler: unicode/obfuscation filter-bypass panel.

Коды возврата (контракт семьи): 0 — фильтр удержал · 1 — обход найден
(finding) · 2 — проверка не состоялась. Только авторизованные/свои цели.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from .banner import SMUGGLER_BANNER
from .tester import run

console = Console()


def _banner() -> None:
    console.print(f"[bold magenta]{SMUGGLER_BANNER}[/bold magenta]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """Unicode/obfuscation filter-bypass panel (MAD battery)."""


@main.command("run")
@click.option("--url", required=True, help="ваш авторизованный агент/эндпоинт")
@click.option("--format", "fmt", type=click.Choice(["openai", "custom", "get"]),
              default="custom", show_default=True)
@click.option("--body", default=None, help='шаблон тела для custom: {"message": "PAYLOAD"}')
@click.option("--key", default=None, help="Bearer-ключ (не попадает в отчёт)")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить структурный отчёт JSON")
def run_cmd(url: str, fmt: str, body: str | None, key: str | None,
            as_json: str | None) -> None:
    """Прогнать панель техник и композиций по одной цели."""
    report = run(url, fmt=fmt, body=body, key=key)
    if as_json:
        Path(as_json).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    for f in report["findings"]:
        console.print(f"  [red]bypass[/red] {f['technique']} — {f['why']}")
    color = {"held": "green", "finding": "red", "not_proven": "yellow"}[report["status"]]
    console.print(f"  status=[bold {color}]{report['status']}[/] rc={report['rc']} "
                  f"— {report['reason']}")
    raise SystemExit(report["rc"])


@main.command("catalog")
def catalog_cmd() -> None:
    """Показать техники: что видит фильтр и что видит нормализующая цель."""
    from .payloads import catalog
    _banner()
    for name, cols in catalog().items():
        console.print(f"  [bold]{name}[/bold]")
        console.print(f"    raw : {cols['raw']!r}")
        console.print(f"    nfkc: {cols['nfkc']!r}")


if __name__ == "__main__":
    main()
