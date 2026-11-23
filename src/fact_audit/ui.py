"""Minimal Flet UI: pick a project folder, run the audit stages, write the reports."""

import contextlib
import io
from pathlib import Path

import flet as ft

from .engines.deps import load_config, scan
from .main import run_audit
from .report_deps import render


def run_scans(
    target: Path,
    *,
    opengrep: bool = True,
    diff: bool = False,
    deps: bool = True,
    online: bool = False,
    log=print,
) -> list[Path]:
    """Run the selected stages against `target` and write the reports next to it."""
    if not target.is_dir():
        raise ValueError(f"not a directory: {target}")

    written: list[Path] = []
    if opengrep:
        result = _stage(
            log,
            "Running Opengrep...",
            lambda: run_audit(str(target), max_findings=50, baseline="HEAD" if diff else None),
        )
        if result is not None:
            report, _ = result
            output = target / "report.md"
            output.write_text(report, encoding="utf-8")
            written.append(output)
            log(f"Wrote {output}")

    if deps:
        result = _stage(log, "Scanning dependencies...", lambda: _deps_scan(target, online))
        if result is not None:
            output = target / "deps-report.md"
            output.write_text(render(result), encoding="utf-8")
            written.append(output)
            log(f"Wrote {output}")

    return written


def _deps_scan(target: Path, online: bool):
    config = load_config(target)
    config.online = online
    result = scan(str(target), config)
    if online:
        from .engines.feeds import enrich

        enrich(result)
    return result


def _stage(log, label: str, run):
    log(label)
    buffer = io.StringIO()
    try:
        # The engine reports progress on stdout/stderr; surface it in the UI instead.
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            value = run()
    except Exception as exc:
        log(f"{label.rstrip('.')} failed: {exc}")
        return None
    progress = buffer.getvalue().strip()
    if progress:
        log(progress)
    return value


def _label(text: str) -> ft.Text:
    return ft.Text(text, size=12, weight=ft.FontWeight.W_600, color=ft.Colors.GREY_700)


def main(page: ft.Page):
    page.title = "fact-audit"
    page.padding = 24
    page.window.width = 780
    page.window.height = 620
    page.window.min_width = 520
    page.window.min_height = 480

    path_field = ft.TextField(
        label="Project folder",
        hint_text=r"C:\path\to\project",
        expand=True,
        autofocus=True,
        on_submit=lambda _: start(None),
    )
    button_shape = ft.RoundedRectangleBorder(radius=8)
    browse_button = ft.OutlinedButton(
        "Browse", icon=ft.Icons.FOLDER_OPEN, style=ft.ButtonStyle(shape=button_shape)
    )

    audit_check = ft.Checkbox(label="Code audit", value=True)
    diff_check = ft.Checkbox(
        label="Changed files only",
        value=False,
        tooltip="Only scan files changed against HEAD.",
    )
    deps_check = ft.Checkbox(label="Dependencies", value=True)
    online_check = ft.Checkbox(
        label="Online lookups",
        value=False,
        tooltip="Fetch advisories, latest versions and licenses from public feeds.",
    )
    diff_check.disabled = not audit_check.value
    online_check.disabled = not deps_check.value

    run_button = ft.FilledButton(
        "Scan", icon=ft.Icons.PLAY_ARROW, style=ft.ButtonStyle(shape=button_shape)
    )
    progress = ft.ProgressRing(width=16, height=16, stroke_width=2, visible=False)
    status = ft.Text("", size=12)

    log_empty = ft.Text("Run output appears here.", size=12, color=ft.Colors.GREY_600)
    log_view = ft.ListView(expand=True, spacing=2, padding=12, auto_scroll=True)
    log_view.controls.append(log_empty)
    log_box = ft.Container(
        expand=True,
        border=ft.Border(
            top=ft.BorderSide(width=1, color=ft.Colors.GREY_300),
            right=ft.BorderSide(width=1, color=ft.Colors.GREY_300),
            bottom=ft.BorderSide(width=1, color=ft.Colors.GREY_300),
            left=ft.BorderSide(width=1, color=ft.Colors.GREY_300),
        ),
        border_radius=8,
        bgcolor=ft.Colors.GREY_50,
        content=log_view,
    )

    async def browse(_event):
        path = await ft.FilePicker().get_directory_path(dialog_title="Select project folder")
        if path:
            path_field.value = path
            path_field.error = None
            page.update()

    def append(text: str):
        if log_empty in log_view.controls:
            log_view.controls.remove(log_empty)
        log_view.controls.append(ft.Text(text, size=12, selectable=True))
        page.update()

    def sync_options(_event=None):
        diff_check.disabled = not bool(audit_check.value)
        online_check.disabled = not bool(deps_check.value)
        page.update()

    def worker(target: str):
        try:
            written = run_scans(
                Path(target),
                opengrep=bool(audit_check.value),
                diff=bool(diff_check.value),
                deps=bool(deps_check.value),
                online=bool(online_check.value),
                log=append,
            )
            status.value = f"Done — {len(written)} report(s) written" if written else "Nothing selected"
            status.color = ft.Colors.GREEN if written else ft.Colors.ORANGE
        except Exception as exc:
            append(f"Error: {exc}")
            status.value = "Failed"
            status.color = ft.Colors.RED
        finally:
            run_button.disabled = False
            progress.visible = False
            page.update()

    def start(_event):
        target = (path_field.value or "").strip()
        path_field.error = None
        if not target:
            path_field.error = "Choose a project folder to scan."
        elif not Path(target).is_dir():
            path_field.error = "That folder does not exist."
        if path_field.error:
            page.update()
            return
        if not (audit_check.value or deps_check.value):
            status.value = "Select at least one scan."
            status.color = ft.Colors.ORANGE
            page.update()
            return
        run_button.disabled = True
        progress.visible = True
        log_view.controls.clear()
        log_view.controls.append(log_empty)
        status.value = "Scanning..."
        status.color = ft.Colors.GREY_700
        page.update()
        page.run_thread(worker, target)

    run_button.on_click = start
    browse_button.on_click = browse
    audit_check.on_change = sync_options
    deps_check.on_change = sync_options

    page.add(
        ft.Column(
            expand=True,
            spacing=20,
            controls=[
                ft.Column(
                    spacing=2,
                    controls=[
                        ft.Text("fact-audit", size=26, weight=ft.FontWeight.BOLD),
                        ft.Text(
                            "Code audit and dependency scan for a local project.",
                            size=13,
                            color=ft.Colors.GREY_700,
                        ),
                    ],
                ),
                ft.Column(
                    spacing=8,
                    controls=[
                        ft.Row(
                            [path_field, browse_button],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Text(
                            "Reports are written into this folder.",
                            size=11,
                            color=ft.Colors.GREY_600,
                        ),
                    ],
                ),
                ft.Column(
                    spacing=4,
                    controls=[
                        _label("Scan options"),
                        ft.Row(
                            [
                                ft.Container(content=audit_check, width=170),
                                diff_check,
                            ],
                            spacing=24,
                        ),
                        ft.Row(
                            [
                                ft.Container(content=deps_check, width=170),
                                online_check,
                            ],
                            spacing=24,
                        ),
                    ],
                ),
                ft.Row(
                    [run_button, progress, status],
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Column(
                    expand=True,
                    spacing=8,
                    controls=[_label("Run log"), log_box],
                ),
            ],
        )
    )


def launch():
    ft.run(main)


if __name__ == "__main__":
    launch()
