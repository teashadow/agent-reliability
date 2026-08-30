"""Template loading and rendering."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from .catalog import PLATFORMS, SEVERITY_CWE, VULN_TYPES


@dataclass(slots=True)
class TemplateContext:
    platform: str
    vuln_type: str
    program: str = "[program name]"
    severity: str = "Medium"
    target: str = "[TARGET]"
    vector: str = "[VECTOR]"
    cvss: str = "[score if applicable]"
    cvss_vector: str = "[CVSS:3.1/...]"
    bug_url: str = "[Bug URL]"
    poc_url: str = "[Proof of concept URL]"
    payload: str = "[Exact payload used]"
    response: str = "[LLM response demonstrating the issue]"


def supported_platforms() -> tuple[str, ...]:
    return PLATFORMS


def supported_types() -> tuple[str, ...]:
    return VULN_TYPES


def validate(platform: str, vuln_type: str) -> None:
    if platform not in PLATFORMS:
        raise ValueError(f"unsupported platform: {platform}")
    if vuln_type not in VULN_TYPES:
        raise ValueError(f"unsupported vulnerability type: {vuln_type}")


def template_text(platform: str, vuln_type: str) -> str:
    validate(platform, vuln_type)
    return resources.files("dt").joinpath("templates", platform, f"{vuln_type}.md").read_text(encoding="utf-8")


def default_context(platform: str, vuln_type: str) -> dict[str, str]:
    validate(platform, vuln_type)
    pretty_type = vuln_type.replace("-", " ").title()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "platform": platform,
        "platform_name": {
            "h1": "HackerOne",
            "bugcrowd": "Bugcrowd",
            "intigriti": "Intigriti",
        }[platform],
        "type": vuln_type,
        "type_label": pretty_type,
        "severity": "Medium",
        "severity_label": "MEDIUM",
        "program": "[program name]",
        "target": "[TARGET]",
        "vector": "[VECTOR]",
        "cvss": "[score if applicable]",
        "cvss_vector": "[CVSS:3.1/...]",
        "cwe": SEVERITY_CWE.get(vuln_type, "CWE-693 (Protection Mechanism Failure)"),
        "bug_url": "[Bug URL]",
        "poc_url": "[Proof of concept URL]",
        "payload": "[Exact payload used]",
        "response": "[LLM response demonstrating the issue]",
        "generated_at": now,
    }


def render_template(platform: str, vuln_type: str, context: dict[str, Any] | None = None) -> str:
    values = default_context(platform, vuln_type)
    if context:
        values.update({k: "" if v is None else str(v) for k, v in context.items()})
    rendered = template_text(platform, vuln_type)
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


# --- пайплайн находка→репорт: заполнить прозаические секции данными находки ---

# нормализованный заголовок секции → ключ находки. Заполняем ТОЛЬКО то, для чего есть данные.
# PoC не тут: у него готовые слоты {{payload}}/{{response}}, заполняем через контекст.
_SECTION_FIELD = {
    "summary": "summary",
    "impact": "impact",
    "steps to reproduce": "steps",
}


def _is_scaffold(line: str) -> bool:
    """Строка-каркас: '[...]', '1. [...]', '- [...]', '```' — то, что подменяем прозой находки."""
    s = line.strip()
    return bool(s) and (s.startswith("[") or s.startswith("- [")
                        or (s[:3].rstrip(". ").isdigit() and "[" in s))


def fill_sections(markdown: str, finding: dict[str, Any]) -> str:
    """Подставить прозу находки под заголовки секций, СОХРАНЯЯ каркас там, где данных нет."""
    lines = markdown.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        header = line.strip().lstrip("#").strip().lower() if line.startswith("#") else None
        field = _SECTION_FIELD.get(header) if header else None
        val = _section_value(field, finding) if field else None
        if val:  # есть чем заменить — проглотить каркасные строки секции, вписать прозу
            i += 1
            # пропустить пустые сразу после заголовка
            while i < len(lines) and not lines[i].strip():
                out.append(lines[i]); i += 1
            заменили = False
            while i < len(lines) and not lines[i].startswith("#"):
                if _is_scaffold(lines[i]):
                    if not заменили:
                        out.append(val); заменили = True
                    # проглотить всю каркасную группу (включая ``` блоки PoC)
                    i += 1
                    continue
                if not заменили and lines[i].strip():
                    out.append(lines[i])
                elif not lines[i].strip():
                    out.append(lines[i])
                i += 1
            continue
        i += 1
    return "\n".join(out)


def _section_value(field: str | None, finding: dict[str, Any]) -> str | None:
    if field == "summary":
        return (finding.get("description") or "").strip() or None
    if field == "impact":
        return (finding.get("impact") or "").strip() or None
    if field == "steps":
        steps = finding.get("steps") or []
        return "\n".join(f"{n}. {s}" for n, s in enumerate(steps, 1)) if steps else None
    return None


def render_report(platform: str, vuln_type: str, finding: dict[str, Any] | None = None) -> str:
    """Контракт пайплайна: finding-JSON (схема finding-organizer) → валидный markdown-репорт."""
    ctx: dict[str, Any] = {}
    if finding:
        ctx = {
            "program": finding.get("program", "[program name]"),
            "severity": str(finding.get("severity", "Medium")).title(),
            "severity_label": str(finding.get("severity", "Medium")).upper(),
            "target": finding.get("target", "[TARGET]"),
            "cvss": finding.get("cvss") or "[score if applicable]",
            # вектор в заголовке: из находки, иначе нейтральное — не оставлять [VECTOR] (машинный tell)
            "vector": finding.get("vector") or "crafted input",
            # PoC-слоты: payload из notes; response нет в схеме находки → честный каркас-подсказка
            "payload": (finding.get("notes") or "[Exact payload used]"),
        }
    md = render_template(platform, vuln_type, context=ctx or None)
    if finding:
        md = fill_sections(md, finding)
    return md


def write_template(
    platform: str,
    vuln_type: str,
    *,
    output_path: str | Path | None = None,
    context: dict[str, Any] | None = None,
) -> Path:
    rendered = render_template(platform, vuln_type, context=context)
    if output_path is None:
        safe_program = (context or {}).get("program", "report")
        safe_program = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in str(safe_program)).strip("-") or "report"
        output_path = Path.cwd() / f"{platform}__{vuln_type}__{safe_program}.md"
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return path
