"""
repo_cloner.py
---------------
Takes a public GitHub repository URL, clones it into a temporary
directory, and hands back a local path that file_walker.py can then
traverse exactly like any local folder.

Design decisions:
- Uses GitPython (wraps the system `git` binary) instead of hitting the
  GitHub API. This avoids GitHub API rate limits entirely and works for
  any git host, not just github.com.
- Clones are SHALLOW (--depth=1) by default: the scanner only needs the
  current state of the code, not full history, and shallow clones are
  dramatically faster/smaller for large repos.
- Caller is responsible for cleanup via cleanup_clone() (or using the
  context-manager form `with clone_repo(...) as path:`), so temp clones
  don't silently accumulate on disk across repeated CLI runs.
"""

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from git import GitCommandError, Repo

# Matches https://github.com/<owner>/<repo>(.git)? and git@github.com:<owner>/<repo>.git
_GITHUB_URL_RE = re.compile(
    r"^(https://github\.com/[\w.\-]+/[\w.\-]+(\.git)?/?|git@github\.com:[\w.\-]+/[\w.\-]+\.git)$"
)


class RepoCloneError(RuntimeError):
    """Raised when a repository cannot be cloned (bad URL, network issue,
    private repo without credentials, etc.)."""


def is_github_url(value: str) -> bool:
    """Return True if `value` looks like a GitHub repo URL (not a local
    path). Used by cli.py to decide which input path to take."""
    return bool(_GITHUB_URL_RE.match(value.strip()))


@contextmanager
def clone_repo(url: str, depth: int = 1) -> Iterator[Path]:
    """Clone `url` into a fresh temp directory and yield the local path.

    Usage:
        with clone_repo("https://github.com/psf/requests") as path:
            files = walk_project(path)
        # temp folder is automatically removed on exit

    Args:
        url: public GitHub repository URL.
        depth: git clone depth. 1 = shallow (default, fastest). Use a
            larger value or None only if a future phase needs history.

    Yields:
        Path to the local clone.

    Raises:
        RepoCloneError: on invalid URL or a git failure (network, auth,
            repo not found, etc.) -- always with a clear cause attached
            so the CLI can print something actionable instead of a raw
            GitPython traceback.
    """
    if not is_github_url(url):
        raise RepoCloneError(f"Not a recognized GitHub repository URL: {url}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="vuln_scanner_clone_"))
    try:
        clone_kwargs = {"depth": depth} if depth else {}
        Repo.clone_from(url, tmp_dir, **clone_kwargs)
        yield tmp_dir
    except GitCommandError as exc:
        raise RepoCloneError(f"Failed to clone {url}: {exc}") from exc
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def clone_repo_persistent(url: str, depth: int = 1) -> Path:
    """Non-context-manager variant for callers (like a future web UI)
    that need the clone to outlive the calling function. The caller MUST
    call cleanup_clone() on the returned path when done.
    """
    if not is_github_url(url):
        raise RepoCloneError(f"Not a recognized GitHub repository URL: {url}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="vuln_scanner_clone_"))
    try:
        clone_kwargs = {"depth": depth} if depth else {}
        Repo.clone_from(url, tmp_dir, **clone_kwargs)
    except GitCommandError as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RepoCloneError(f"Failed to clone {url}: {exc}") from exc
    return tmp_dir


def cleanup_clone(path: Optional[Path]) -> None:
    """Remove a temp clone created by clone_repo_persistent()."""
    if path and Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)