"""
file_walker.py
---------------
Recursively walks a local project folder and returns the list of source
files that should be handed to the AST parser (Phase 2).

Design decisions:
- We exclude directories BY NAME during the walk (not after), so os.walk
  never even descends into them. This matters for large repos like ones
  with a bloated node_modules/ -- descending into it first and filtering
  after would be extremely wasteful.
- Exclusion is name-based (dir basename match), not path-based, so a
  nested "build" folder anywhere in the tree is excluded, not just a
  top-level one.
- Phase 1 targets Python only, so we filter to *.py files. Other
  languages can be added later by extending SUPPORTED_EXTENSIONS.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Set

# Directory names that should never be descended into. These are either
# dependency/vendor folders, VCS internals, or build output -- none of
# which contain first-party source code worth scanning.
DEFAULT_EXCLUDES: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "site-packages",
    "egg-info",
}

# Phase 1 is Python-only, per the project brief's "support one language
# deeply" requirement.
SUPPORTED_EXTENSIONS: Set[str] = {".py"}


@dataclass
class ScannedFile:
    """A single source file discovered by the walker, with paths kept
    relative to the scan root so reports don't leak the local filesystem
    layout (e.g. /home/username/...) into shareable output."""

    absolute_path: Path
    relative_path: Path
    size_bytes: int = field(default=0)

    def __post_init__(self):
        if self.size_bytes == 0:
            try:
                self.size_bytes = self.absolute_path.stat().st_size
            except OSError:
                self.size_bytes = 0

    def __repr__(self) -> str:
        return f"ScannedFile({self.relative_path})"


def _is_excluded_dir(dirname: str, excludes: Set[str]) -> bool:
    """Match by exact name and by suffix for things like '*.egg-info'."""
    if dirname in excludes:
        return True
    if dirname.endswith(".egg-info"):
        return True
    return False


def walk_project(
    root: str | os.PathLike,
    extensions: Iterable[str] = SUPPORTED_EXTENSIONS,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    max_file_size_bytes: int = 2_000_000,
) -> List[ScannedFile]:
    """Recursively walk `root` and return every source file matching
    `extensions`, skipping any directory in `excludes`.

    Args:
        root: local folder path to scan.
        extensions: file extensions to include (default: Python only).
        excludes: directory basenames to skip entirely.
        max_file_size_bytes: files larger than this are skipped -- a
            multi-MB "python" file is almost always generated/vendored
            code (e.g. a bundled grammar or data file), not something a
            human wrote, and parsing it wastes time for little value.

    Returns:
        A list of ScannedFile, sorted by relative path for deterministic
        output (important later for reproducible reports/tests).

    Raises:
        NotADirectoryError: if root does not exist or isn't a directory.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_path}")

    exclude_set = set(excludes)
    ext_set = {e if e.startswith(".") else f".{e}" for e in extensions}

    found: List[ScannedFile] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune excluded directories in-place so os.walk skips them.
        dirnames[:] = sorted(
            d for d in dirnames if not _is_excluded_dir(d, exclude_set)
        )

        for filename in filenames:
            if Path(filename).suffix not in ext_set:
                continue

            abs_path = Path(dirpath) / filename

            try:
                if abs_path.stat().st_size > max_file_size_bytes:
                    continue
            except OSError:
                # File vanished or is unreadable (broken symlink, perms) --
                # skip rather than crash the whole scan.
                continue

            found.append(
                ScannedFile(
                    absolute_path=abs_path,
                    relative_path=abs_path.relative_to(root_path),
                )
            )

    found.sort(key=lambda f: str(f.relative_path))
    return found


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    files = walk_project(target)
    print(f"Found {len(files)} Python file(s) under {Path(target).resolve()}:")
    for f in files:
        print(f"  {f.relative_path}  ({f.size_bytes} bytes)")