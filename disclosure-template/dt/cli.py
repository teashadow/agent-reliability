"""CLI entrypoint for inkwell."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from .banner import INKWELL_BANNER
from .renderer import (render_report, render_template, supported_platforms,
                       supported_types, write_template)

console = Console()


def _print_banner() -> None:
    console.print(f"[bold cyan]{INKWELL_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _print_banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD disclosure templates."""


@main.command("list-types")
def list_types() -> None:
    """List supported vulnerability types."""
    table = Table(title="Supported Types")
    table.add_column("Type", style="magenta")
    for item in supported_types():
        table.add_row(item)
    console.print(table)


@main.command("list-platforms")
def list_platforms() -> None:
    """List supported platforms."""
    table = Table(title="Supported Platforms")
    table.add_column("Platform", style="green")
    for item in supported_platforms():
        table.add_row(item)
    console.print(table)


@main.command("preview")
@click.option("--platform", default="h1", show_default=True)
@click.option("--type", "vuln_type", required=True)
def preview(platform: str, vuln_type: str) -> None:
    """Preview a template in the terminal."""
    console.print(Markdown(render_template(platform, vuln_type)))


@main.command("new")
@click.option("--platform", required=True, type=click.Choice(supported_platforms()))
@click.option("--type", "vuln_type", required=True, type=click.Choice(supported_types()))
@click.option("--program", default="[program name]", show_default=True)
@click.option("--severity", default="Medium", show_default=True)
@click.option("--target", default="[TARGET]", show_default=True)
@click.option("--output", type=click.Path(path_type=Path))
def new(platform: str, vuln_type: str, program: str, severity: str, target: str, output: Path | None) -> None:
    """Create a new markdown report file."""
    path = write_template(
        platform,
        vuln_type,
        output_path=output,
        context={"program": program, "severity": severity, "severity_label": severity.upper(), "target": target},
    )
    console.print(f"[green]Wrote[/green] {path}")


@main.command("from-finding")
@click.argument("finding_json", type=click.Path(exists=True, path_type=Path))
@click.option("--platform", default=None, help="переопределить платформу (иначе из находки)")
@click.option("--output", type=click.Path(path_type=Path), help="сохранить черновик репорта")
def from_finding(finding_json: Path, platform: str | None, output: Path | None) -> None:
    """Развернуть находку (JSON из общей БД finding-organizer) в черновик H1-репорта."""
    import json

    finding = json.loads(finding_json.read_text(encoding="utf-8"))
    plat = platform or finding.get("platform", "h1")
    if plat not in supported_platforms():
        plat = "h1"
    vuln_type = finding.get("type", "prompt-injection")
    if vuln_type not in supported_types():
        raise SystemExit(f"тип '{vuln_type}' не поддержан шаблонами: {', '.join(supported_types())}")
    md = render_report(plat, vuln_type, finding=finding)
    if output:
        output.write_text(md, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output}")
    else:
        console.print(Markdown(md))


if __name__ == "__main__":
    main()
