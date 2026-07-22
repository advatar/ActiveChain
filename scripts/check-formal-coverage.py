#!/usr/bin/env python3
"""Fail when a checked-in Lean module or Tamarin lemma is omitted by CI."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def require_unique_exact(label: str, declared: list[str], selected: list[str]) -> None:
    if len(selected) != len(set(selected)):
        raise SystemExit(f"{label}: duplicate selector")
    missing = sorted(set(declared) - set(selected))
    stale = sorted(set(selected) - set(declared))
    if missing or stale:
        raise SystemExit(f"{label}: missing={missing}, stale={stale}")


def audit_lean() -> int:
    lean = ROOT / "formal/lean"
    root_imports = set(re.findall(r"^import\s+(\S+)", (lean / "ActiveChain.lean").read_text(), re.M))
    library_modules = [f"ActiveChain.{path.stem}" for path in (lean / "ActiveChain").glob("*.lean")]
    require_unique_exact("Lean library imports", library_modules, sorted(root_imports))

    lakefile = (lean / "lakefile.toml").read_text()
    executable_roots = re.findall(r'^root\s*=\s*"([^"]+)"', lakefile, re.M)
    top_level = [path.stem for path in lean.glob("*.lean") if path.name != "ActiveChain.lean"]
    require_unique_exact("Lean executable roots", top_level, executable_roots)
    default_targets_match = re.search(r"defaultTargets\s*=\s*\[([^]]+)\]", lakefile)
    if default_targets_match is None:
        raise SystemExit("Lean default targets are missing")
    defaults = re.findall(r'"([^"]+)"', default_targets_match.group(1))
    executable_names = re.findall(r'^name\s*=\s*"([^"]+)"\nroot\s*=', lakefile, re.M)
    require_unique_exact("Lean default executable targets", executable_names, defaults[1:])
    if not defaults or defaults[0] != "ActiveChain":
        raise SystemExit("Lean library is not the first default target")
    return 1 + len(library_modules) + len(executable_roots)


def audit_tamarin() -> tuple[int, int]:
    theories = 0
    lemmas = 0
    for model in sorted((ROOT / "formal/tamarin").glob("*.spthy")):
        theories += 1
        declared = re.findall(r"^lemma\s+([A-Za-z0-9_]+)", model.read_text(), re.M)
        if not declared:
            raise SystemExit(f"{model.name}: no lemmas declared")
        lemmas += len(declared)
        selector = model.with_suffix(".lemmas")
        unproved_file = model.with_suffix(".unproved")
        unproved = (
            [line.strip() for line in unproved_file.read_text().splitlines() if line.strip()]
            if unproved_file.exists()
            else []
        )
        if selector.exists():
            selected = [line.strip() for line in selector.read_text().splitlines() if line.strip()]
            if set(selected) & set(unproved):
                raise SystemExit(f"{model.name}: lemma is both selected and unproved")
            require_unique_exact(model.name, declared, selected + unproved)
        elif unproved:
            raise SystemExit(f"{model.name}: unproved list requires an explicit selector")
    if theories == 0:
        raise SystemExit("no Tamarin theories discovered")
    return theories, lemmas


def mutation_audit() -> None:
    try:
        require_unique_exact("duplicate", ["a"], ["a", "a"])
    except SystemExit:
        pass
    else:
        raise AssertionError("duplicate selector mutation was accepted")
    for selected in ([], ["stale"]):
        try:
            require_unique_exact("mutation", ["a"], selected)
        except SystemExit:
            pass
        else:
            raise AssertionError("missing/stale selector mutation was accepted")


if __name__ == "__main__":
    mutation_audit()
    lean_count = audit_lean()
    theory_count, lemma_count = audit_tamarin()
    print(f"formal coverage: {lean_count} Lean targets/modules, {theory_count} Tamarin theories, {lemma_count} classified lemmas")
