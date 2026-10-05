"""Shared helpers for the repository's check, conversion and regression-test scripts."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

ROOT = Path(__file__).resolve().parent.parent

# Root folders that hold active rules (see CONVENTIONS.md, section 1).
RULE_DIRS = ("rules", "rules-threat-hunting", "rules-emerging-threats")


def iter_rule_files(root: Path = ROOT) -> Iterator[Path]:
    """Yield every rule file under the active rule folders, sorted for stable output."""
    for name in RULE_DIRS:
        folder = root / name
        if folder.is_dir():
            yield from sorted(folder.rglob("*.yml"))


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def rel(path: Path, root: Path = ROOT) -> str:
    """Repo-relative path with forward slashes, for messages and comparisons."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


@lru_cache(maxsize=1)
def sigma_plugins() -> InstalledSigmaPlugins:
    return InstalledSigmaPlugins.autodiscover()


def resolve_pipeline(specs: Iterable[str], target: str | None = None, root: Path = ROOT) -> ProcessingPipeline:
    """Resolve pipeline specs the way `sigma convert -p` does.

    A spec is either a repo-relative path to a YAML pipeline or the name of an installed
    pipeline such as ``ecs_windows``. With a target, pipelines not meant for that backend
    are rejected, as sigma-cli does.
    """
    resolved = [str(root / spec) if (root / spec).is_file() else spec for spec in specs]
    return sigma_plugins().get_pipeline_resolver().resolve(resolved, target)


def iter_detection_items(rule: SigmaRule) -> Iterator[SigmaDetectionItem]:
    """Yield every detection item of a rule, descending into nested detections."""

    def walk(detection: SigmaDetection) -> Iterator[SigmaDetectionItem]:
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                yield from walk(item)
            else:
                yield item

    for detection in rule.detection.detections.values():
        yield from walk(detection)


def write_step_summary(markdown: str) -> None:
    """Append to the GitHub Actions job summary when running in CI."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
