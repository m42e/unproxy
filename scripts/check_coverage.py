#!/usr/bin/env python3
"""Fail a cargo-llvm-cov JSON report below project coverage objectives."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PORTABLE_FILES = {
    "access.rs",
    "auth.rs",
    "config.rs",
    "connection.rs",
    "dns.rs",
    "net.rs",
    "network_notifications.rs",
    "pac.rs",
    "proxy.rs",
    "route.rs",
    "runtime.rs",
}
NATIVE_FILES = {"auth/native.rs", "network_notifications/macos.rs"}


def source_path(filename: str) -> str:
    return filename.replace("\\", "/")


def sum_metrics(files: list[dict], metric: str) -> tuple[int, int]:
    covered = sum(file["summary"][metric]["covered"] for file in files)
    count = sum(file["summary"][metric]["count"] for file in files)
    return covered, count


def percentage(covered: int, count: int) -> float:
    return 100.0 * covered / count if count else 100.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="cargo llvm-cov JSON report")
    args = parser.parse_args()

    try:
        document = json.loads(args.report.read_text(encoding="utf-8"))
        report = document["data"][0]
        files = report["files"]
        totals = report["totals"]
    except (OSError, KeyError, IndexError, json.JSONDecodeError) as error:
        print(f"cannot read LLVM coverage report {args.report}: {error}", file=sys.stderr)
        return 2

    portable = [
        file
        for file in files
        if any(source_path(file["filename"]).endswith(f"/src/{name}") for name in PORTABLE_FILES)
    ]
    found = {source_path(file["filename"]).rsplit("/", 1)[-1] for file in portable}
    missing = sorted(PORTABLE_FILES - found)
    if missing:
        print(f"report is missing portable source files: {', '.join(missing)}", file=sys.stderr)
        return 2

    native = [
        file
        for file in files
        if any(source_path(file["filename"]).endswith(f"/src/{name}") for name in NATIVE_FILES)
    ]
    failures = []
    for scope, metrics, line_floor, region_floor in (
        ("total", totals, 90.0, 85.0),
        ("portable", None, 95.0, 90.0),
    ):
        for metric, floor in (("lines", line_floor), ("regions", region_floor)):
            if scope == "total":
                covered = metrics[metric]["covered"]
                count = metrics[metric]["count"]
            else:
                covered, count = sum_metrics(portable, metric)
            actual = percentage(covered, count)
            print(f"{scope:8} {metric:7} {actual:6.2f}% ({covered}/{count}), required {floor:.0f}%")
            if actual + 1e-9 < floor:
                failures.append(f"{scope} {metric} {actual:.2f}% is below {floor:.0f}%")

    for file in native:
        path = source_path(file["filename"])
        for metric in ("lines", "regions"):
            summary = file["summary"][metric]
            print(
                f"native   {path.rsplit('/src/', 1)[-1]:34} {metric:7} "
                f"{percentage(summary['covered'], summary['count']):6.2f}% "
                f"({summary['covered']}/{summary['count']})"
            )
    if failures:
        for failure in failures:
            print(f"coverage gate failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
