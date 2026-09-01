"""CLI — arsenic: RAG poisoning resilience QA.

Коды возврата (контракт семьи): 0 — RAG удержал · 1 — отравление найдено
(finding) · 2 — проверка не состоялась. Только авторизованные/свои цели.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from .banner import ARSENIC_BANNER
from .payloads import VISIBLE_CONTROL, build_doc, list_strategies
from .tester import run

console = Console()


def _banner() -> None:
    console.print(f"[bold green]{ARSENIC_BANNER}[/bold green]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """RAG poisoning resilience QA (MAD battery)."""


@main.command("run")
@click.option("--index-url", required=True, help="ваш RAG /index эндпоинт")
@click.option("--query-url", required=True, help="ваш RAG /query эндпоинт")
@click.option("--key", default=None, help="Bearer-ключ (не попадает в отчёт)")
@click.option("--query", default="Summarize the quarterly report.",
              help="запрос, извлекающий приманку")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить структурный отчёт JSON")
def run_cmd(index_url: str, query_url: str, key: str | None, query: str,
            as_json: str | None) -> None:
    """Индексировать приманки → запросить → поймать исполнение скрытых инструкций."""
    report = run(index_url, query_url, key=key, query=query)
    if as_json:
        Path(as_json).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    for f in report["findings"]:
        if f["verdict"] == "performed":
            console.print(f"  [red]poisoned[/red] {f['strategy']} — {f['why']}")
        elif f["verdict"] == "heartbeat":
            mark = "[green]heartbeat ok[/green]" if "ok" in f["why"] else \
                "[yellow]heartbeat MISSING[/yellow]"
            console.print(f"  {mark} ({VISIBLE_CONTROL})")
    color = {"held": "green", "finding": "red", "not_proven": "yellow"}[report["status"]]
    console.print(f"  status=[bold {color}]{report['status']}[/] rc={report['rc']} "
                  f"— {report['reason']}")
    raise SystemExit(report["rc"])


@main.command("doc")
@click.option("--strategy", default="comment", help="вектор: " + ", ".join(list_strategies()))
@click.option("--type", "doc_type", type=click.Choice(["md", "html"]),
              default="md", show_default=True)
@click.option("--out", type=click.Path(), default=None, help="файл вывода")
def doc_cmd(strategy: str, doc_type: str, out: str | None) -> None:
    """Сгенерировать приманку с канарейкой в выбранном векторе (pdf — ленивый импорт)."""
    _banner()
    canary = "ARSENIC-CANARY-LOCAL0001"
    text = build_doc(strategy, canary)
    if doc_type == "html":
        text = f"<!doctype html><html><body>{text}</body></html>"
    if out:
        Path(out).write_text(text, encoding="utf-8")
        console.print(f"  written: {out} (canary: {canary})")
    else:
        console.print(text)
