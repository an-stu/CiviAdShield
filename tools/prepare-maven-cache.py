#!/usr/bin/env python3
"""Mirror Gradle's immutable artifact cache into this project's Maven layout."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

ARTIFACT_SUFFIXES = {".jar", ".pom", ".module", ".aar"}


def maven_destination(cache_root: Path, repo_root: Path, artifact: Path) -> Path | None:
    """Map a Gradle files-2.1 artifact to Maven's group/module/version layout."""
    try:
        parts = artifact.relative_to(cache_root).parts
    except ValueError:
        return None
    if len(parts) != 5 or Path(parts[-1]).suffix not in ARTIFACT_SUFFIXES:
        return None
    group, module, version, _content_hash, filename = parts
    group_path = Path(*group.split("."))
    return repo_root / group_path / module / version / filename


def materialize(cache_root: Path, repo_root: Path) -> tuple[int, int]:
    linked = 0
    copied = 0
    cache_root = cache_root.resolve()
    repo_root.mkdir(parents=True, exist_ok=True)

    for artifact in cache_root.rglob("*"):
        if not artifact.is_file():
            continue
        destination = maven_destination(cache_root, repo_root, artifact)
        if destination is None:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.stat().st_size != artifact.stat().st_size:
                raise RuntimeError(f"Refusing to replace different artifact: {destination}")
            if destination.read_bytes() != artifact.read_bytes():
                raise RuntimeError(f"Refusing to replace different artifact: {destination}")
            continue
        try:
            os.link(artifact, destination)
            linked += 1
        except OSError:
            shutil.copy2(artifact, destination)
            copied += 1
    return linked, copied


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache-root",
        type=Path,
        default=Path.home() / ".gradle/caches/modules-2/files-2.1",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ".toolchain/maven",
    )
    args = parser.parse_args()
    if not args.cache_root.is_dir():
        parser.error(f"Gradle artifact cache not found: {args.cache_root}")
    linked, copied = materialize(args.cache_root, args.repo_root)
    print(f"Materialized Maven artifacts: {linked} hard links, {copied} copies")


if __name__ == "__main__":
    main()
