#!/usr/bin/env python3
"""Render all tray icon states from the native AppKit vector drawing.

Requires Swift and ImageMagick. These tools are only needed to update the
checked-in icons; users and release builds consume the generated files.
"""

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets/tray-icons"

def run(*args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, check=True, env=env)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for stale in (*OUTPUT.glob("*.png"), *OUTPUT.glob("*.ico")):
        stale.unlink()
    with tempfile.TemporaryDirectory(prefix="unproxy-swift-cache-") as cache:
        swift_env = os.environ.copy()
        swift_env["CLANG_MODULE_CACHE_PATH"] = cache
        swift_env["SWIFT_MODULE_CACHE_PATH"] = cache
        run(
            "swift",
            str(ROOT / "scripts/render_tray_icons.swift"),
            str(OUTPUT),
            env=swift_env,
        )
    for png_path in OUTPUT.glob("*.png"):
        run(
            "magick",
            str(png_path),
            "-define",
            "icon:auto-resize=64,48,32,24,20,16",
            str(png_path.with_suffix(".ico")),
        )


if __name__ == "__main__":
    main()
