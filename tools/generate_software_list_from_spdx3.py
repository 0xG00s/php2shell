#!/usr/bin/env python3
"""Generate alphabetized Markdown software lists from an SPDX 3 inventory."""

from __future__ import annotations

import argparse
import json
import re
import string
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any

TITLE = "List of software with PHP dependency potentially affected by php2shell CVEs"
BUCKETS = ["0-9", *string.ascii_uppercase]
DEFAULT_SPDX_DIR = Path("software") / "spdx"
VEX_STATUS_MAP = {
    "underInvestigationFor": "Investigation",
    "affects": "Vulnerable",
    "fixedIn": "Fix",
    "doesNotAffect": "Not vuln",
}


class GenerationError(ValueError):
    """Raised when an SPDX document cannot be rendered safely."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate alphabetized Markdown software lists from SPDX 3 JSON.",
    )
    parser.add_argument(
        "spdx_filename",
        type=Path,
        help="SPDX filename in software/spdx, or a path to an SPDX 3 JSON document",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("software"),
        help="Output directory. Default: software",
    )
    return parser.parse_args(argv)


def resolve_spdx_path(spdx_filename: Path) -> Path:
    if spdx_filename.is_absolute() or spdx_filename.parent != Path(".") or spdx_filename.exists():
        return spdx_filename
    return DEFAULT_SPDX_DIR / spdx_filename


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise GenerationError(f"Input file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GenerationError(f"Input file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("@graph"), list):
        raise GenerationError("Expected an SPDX JSON object with an '@graph' array.")
    return data


def raw_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return str(value)


def ascii_text(value: Any) -> str:
    value_text = raw_text(value) or ""
    replacements = {
        "\u00a0": " ",
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2192": "->",
    }
    for source, replacement in replacements.items():
        value_text = value_text.replace(source, replacement)
    return unicodedata.normalize("NFKD", value_text).encode("ascii", "ignore").decode("ascii")


def markdown_cell(value: Any) -> str:
    value_text = ascii_text(value)
    value_text = value_text.replace("\\", "\\\\")
    value_text = value_text.replace("|", "\\|")
    value_text = re.sub(r"\r?\n+", "<br>", value_text)
    return value_text.strip()


def markdown_link(label: str, url: str) -> str:
    return f"[{markdown_cell(label)}](<{ascii_text(url)}>)"


def markdown_relative_link(label: str, path: str) -> str:
    return f"[{markdown_cell(label)}]({ascii_text(path)})"


def graph_by_type(graph: list[dict[str, Any]], element_type: str) -> list[dict[str, Any]]:
    return [element for element in graph if element.get("type") == element_type]


def organization_names(graph: list[dict[str, Any]]) -> dict[str, str]:
    return {
        element["spdxId"]: raw_text(element.get("name")) or "Unknown"
        for element in graph_by_type(graph, "Organization")
        if raw_text(element.get("spdxId"))
    }


def vulnerability_ids(graph: list[dict[str, Any]]) -> dict[str, str]:
    vulnerabilities = {}
    for element in graph_by_type(graph, "security_Vulnerability"):
        spdx_id = raw_text(element.get("spdxId"))
        name = raw_text(element.get("name"))
        if spdx_id and name:
            vulnerabilities[spdx_id] = name
    return vulnerabilities


def package_statuses(
    graph: list[dict[str, Any]],
    vulnerability_names: dict[str, str],
) -> tuple[dict[str, dict[str, str]], dict[str, list[str]]]:
    statuses: defaultdict[str, dict[str, str]] = defaultdict(dict)
    notes: defaultdict[str, list[str]] = defaultdict(list)

    for element in graph:
        element_type = raw_text(element.get("type")) or ""
        if not element_type.startswith("security_Vex"):
            continue
        cve = vulnerability_names.get(raw_text(element.get("from")) or "")
        if not cve:
            continue
        relationship_type = raw_text(element.get("relationshipType")) or ""
        status = VEX_STATUS_MAP.get(relationship_type, relationship_type or "Unknown")
        status_note = raw_text(element.get("security_statusNotes"))
        for package_id in element.get("to") or []:
            existing = statuses[package_id].get(cve)
            if existing and existing != status:
                raise GenerationError(
                    f"Conflicting VEX statuses for {package_id} and {cve}: {existing} vs {status}"
                )
            statuses[package_id][cve] = status
            if status_note and status_note not in notes[package_id]:
                notes[package_id].append(status_note)

    return dict(statuses), dict(notes)


def external_links(package: dict[str, Any]) -> str:
    refs = package.get("externalRef") or []
    urls: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        locators = ref.get("locator") or []
        if isinstance(locators, str):
            locators = [locators]
        for locator in locators:
            locator_text = raw_text(locator)
            if locator_text and locator_text not in urls:
                urls.append(locator_text)

    if not urls:
        return ""
    if len(urls) == 1:
        return markdown_link("source", urls[0])
    return "<br>".join(markdown_link(f"source {index}", url) for index, url in enumerate(urls, 1))


def package_notes(package: dict[str, Any], status_notes: list[str]) -> str:
    parts: list[str] = []
    if status_notes:
        parts.append("CVE assessment: " + "; ".join(status_notes))
    summary = raw_text(package.get("summary"))
    if summary:
        parts.append(summary)
    return markdown_cell("\n".join(parts))


def bucket_for_supplier(supplier: str) -> str:
    first = ascii_text(supplier)[:1].upper()
    if first in string.ascii_uppercase:
        return first
    return "0-9"


def build_entries(document: dict[str, Any]) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    graph = document["@graph"]
    orgs = organization_names(graph)
    vulnerabilities = vulnerability_ids(graph)
    cves = sorted(vulnerabilities.values())
    statuses, status_notes = package_statuses(graph, vulnerabilities)
    buckets: defaultdict[str, list[dict[str, str]]] = defaultdict(list)

    for package in graph_by_type(graph, "software_Package"):
        package_id = raw_text(package.get("spdxId"))
        product = raw_text(package.get("name"))
        if not package_id or not product:
            raise GenerationError("Each software_Package must have 'spdxId' and 'name'.")
        supplier = orgs.get(raw_text(package.get("suppliedBy")) or "", "Unknown")
        entry = {
            "supplier": markdown_cell(supplier),
            "product": markdown_cell(product),
            "version": markdown_cell(package.get("software_packageVersion")),
            "notes": package_notes(package, status_notes.get(package_id, [])),
            "links": external_links(package),
        }
        for cve in cves:
            entry[cve] = markdown_cell(statuses.get(package_id, {}).get(cve, ""))
        buckets[bucket_for_supplier(supplier)].append(entry)

    for entries in buckets.values():
        entries.sort(key=lambda item: (item["supplier"].casefold(), item["product"].casefold()))
    return cves, dict(buckets)


def navigation_line() -> str:
    links = [markdown_relative_link(bucket, f"software_list_{bucket.lower()}.md") for bucket in BUCKETS]
    return " ".join(links)


def table_header(cves: list[str]) -> list[str]:
    columns = [
        "Supplier",
        "Product",
        "Version (see Status)",
        *[f"Status {cve}" for cve in cves],
        "Notes",
        "Links",
    ]
    alignment = [":---------", ":--------", ":--------------------:", *[":----------------------:" for _ in cves], ":------", "------:"]
    return [
        "| " + " | ".join(columns) + " |",
        "|" + "|".join(alignment) + "|",
    ]


def render_index() -> str:
    return "\n".join(
        [
            f"# {TITLE}",
            "[About this list](README.md)",
            "",
            navigation_line(),
            "",
        ]
    )


def render_bucket(bucket: str, cves: list[str], entries: list[dict[str, str]]) -> str:
    lines = [
        f"# {TITLE}",
        "[About this list](README.md)",
        "",
        navigation_line(),
        "",
        f"### {bucket}",
        "",
        *table_header(cves),
    ]
    for entry in entries:
        row = [
            entry["supplier"],
            entry["product"],
            entry["version"],
            *[entry.get(cve, "") for cve in cves],
            entry["notes"],
            entry["links"],
        ]
        lines.append("|" + "|".join(row) + "|")
    lines.append("")
    return "\n".join(lines)


def write_lists(document: dict[str, Any], output_dir: Path) -> tuple[int, dict[str, int]]:
    cves, buckets = build_entries(document)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "software_list.md").write_text(render_index(), encoding="utf-8", newline="\n")

    counts: dict[str, int] = {}
    for bucket in BUCKETS:
        entries = buckets.get(bucket, [])
        counts[bucket] = len(entries)
        path = output_dir / f"software_list_{bucket.lower()}.md"
        path.write_text(render_bucket(bucket, cves, entries), encoding="utf-8", newline="\n")
    return sum(counts.values()), counts


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        document = load_json(resolve_spdx_path(args.spdx_filename))
        total, counts = write_lists(document, args.output_dir)
    except GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    populated = ", ".join(f"{bucket}={count}" for bucket, count in counts.items() if count)
    print(f"Wrote {total} software rows to {args.output_dir}. Populated buckets: {populated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
