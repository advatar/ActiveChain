#!/usr/bin/env python3
"""Validate the public contributor documentation without third-party packages."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
DOCUMENTS = (
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "LICENSE",
    "docs/README.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
)
MARKDOWN_DOCUMENTS = tuple(path for path in DOCUMENTS if path.endswith(".md"))
README_HEADINGS = (
    "## Current maturity",
    "## Quick start",
    "## Repository map",
    "## Development workflow",
    "## Security status",
    "## Community and governance",
    "## License",
)
LINK_PATTERN = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def main() -> None:
    missing_documents = [path for path in DOCUMENTS if not (ROOT / path).is_file()]
    if missing_documents:
        raise SystemExit(f"missing community documents: {', '.join(missing_documents)}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing_headings = [heading for heading in README_HEADINGS if heading not in readme]
    if missing_headings:
        raise SystemExit(f"README is missing headings: {', '.join(missing_headings)}")

    broken_links: list[str] = []
    for relative_path in MARKDOWN_DOCUMENTS:
        source = ROOT / relative_path
        for raw_target in LINK_PATTERN.findall(source.read_text(encoding="utf-8")):
            target = raw_target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            if not (source.parent / target).resolve().exists():
                broken_links.append(f"{relative_path}: {raw_target}")
    if broken_links:
        raise SystemExit("broken local Markdown links:\n" + "\n".join(broken_links))

    print(f"community documentation OK ({len(DOCUMENTS)} required files)")


if __name__ == "__main__":
    main()
