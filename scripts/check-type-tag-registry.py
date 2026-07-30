#!/usr/bin/env python3
"""Verify the authoritative ActiveChain canonical type-tag registry."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "testing" / "type-tag-registry-v1.tsv"
IMPL = re.compile(r"impl\s+CanonicalType\s+for\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
INHERENT = re.compile(r"impl\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
TAG = re.compile(r"const\s+TYPE_TAG:\s*u16\s*=\s*(0x[0-9A-Fa-f]+|Self::TYPE_TAG)")
SCHEMA = re.compile(
    r"const\s+SCHEMA_VERSION:\s*u16\s*=\s*([A-Za-z_][A-Za-z0-9_:]*|[0-9]+|Self::SCHEMA_VERSION)"
)
OWN_TAG = re.compile(r"(?:pub\s+)?const\s+TYPE_TAG:\s*u16\s*=\s*(0x[0-9A-Fa-f]+)")
OWN_SCHEMA = re.compile(r"(?:pub\s+)?const\s+SCHEMA_VERSION:\s*u16\s*=\s*([0-9]+)")


def block(text: str, opening: int) -> str:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening : index + 1]
    raise ValueError("unclosed Rust block")


def production_text(text: str) -> str:
    """Remove test/proof modules without discarding production items that follow them."""
    matches = list(
        re.finditer(r"#\[cfg\((?:test|kani)\)\]\s*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", text)
    )
    for match in reversed(matches):
        opening = text.find("{", match.start(), match.end())
        body = block(text, opening)
        text = text[: match.start()] + text[opening + len(body) :]
    return text


def numeric_schema(expression: str, own: str | None) -> int:
    if expression.isdigit():
        return int(expression)
    if expression == "Self::SCHEMA_VERSION" and own is not None:
        return int(own)
    # All named revision constants used by canonical v1 types currently resolve to one.
    if expression.endswith("REVISION") or expression.endswith("VERSION"):
        return 1
    raise ValueError(f"unresolved schema expression: {expression}")


def inventory() -> list[tuple[int, int, str, str]]:
    entries: list[tuple[int, int, str, str]] = []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if relative.endswith("canonical-codec/src/kani_proofs.rs"):
            continue
        text = production_text(path.read_text())
        inherent: dict[str, tuple[str | None, str | None]] = {}
        for match in INHERENT.finditer(text):
            body = block(text, match.end() - 1)
            tag = OWN_TAG.search(body)
            schema = OWN_SCHEMA.search(body)
            if tag or schema:
                inherent[match.group(1)] = (
                    tag.group(1) if tag else None,
                    schema.group(1) if schema else None,
                )
        for match in IMPL.finditer(text):
            type_name = match.group(1)
            body = block(text, match.end() - 1)
            tag_match = TAG.search(body)
            schema_match = SCHEMA.search(body)
            if not tag_match or not schema_match:
                raise ValueError(f"incomplete CanonicalType implementation: {relative}::{type_name}")
            own_tag, own_schema = inherent.get(type_name, (None, None))
            tag_expression = tag_match.group(1)
            if tag_expression == "Self::TYPE_TAG":
                if own_tag is None:
                    raise ValueError(f"unresolved type tag: {relative}::{type_name}")
                tag_expression = own_tag
            entries.append(
                (
                    int(tag_expression, 16),
                    numeric_schema(schema_match.group(1), own_schema),
                    type_name,
                    relative,
                )
            )
        for macro in ("canonical_type", "relation_codec"):
            pattern = re.compile(
                rf"{macro}!\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(0x[0-9A-Fa-f]+)", re.S
            )
            for match in pattern.finditer(text):
                entries.append((int(match.group(2), 16), 1, match.group(1), relative))
    return sorted(set(entries))


def load_registry() -> list[tuple[int, int, str, str]]:
    rows = []
    for number, line in enumerate(REGISTRY.read_text().splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValueError(f"invalid registry row {number}")
        rows.append((int(fields[0], 16), int(fields[1]), fields[2], fields[3]))
    return sorted(rows)


def main() -> int:
    actual = inventory()
    expected = load_registry()
    if actual != expected:
        missing = sorted(set(actual) - set(expected))
        stale = sorted(set(expected) - set(actual))
        print(f"type-tag registry mismatch; missing={missing!r}; stale={stale!r}", file=sys.stderr)
        return 1
    by_tag: dict[int, tuple[int, str, str]] = {}
    for tag, schema, type_name, source in actual:
        if tag in by_tag:
            print(
                f"type-tag collision 0x{tag:04x}: {by_tag[tag][1:]} and {(type_name, source)}",
                file=sys.stderr,
            )
            return 1
        if not (0x0020 <= tag <= 0x00D9 or 0x0100 <= tag <= 0x01FF):
            print(f"tag outside v1 registry or in reserved extension space: 0x{tag:04x}", file=sys.stderr)
            return 1
        by_tag[tag] = (schema, type_name, source)
    print(f"canonical type-tag registry verified: {len(actual)} unique production types")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
