"""
ast_parser.py
-------------
Converts source files (ScannedFile objects from Phase 1's file_walker)
into Python ASTs (Abstract Syntax Trees) using the built-in `ast` module.

This is the foundation every later phase builds on:
    Phase 3 (complexity/unused vars/nesting/dead code) walks these trees.
    Phase 4 (vulnerability rules) walks these trees.
    Phase 6 (taint tracking) walks these trees.
None of those phases re-read or re-parse files themselves -- they all
consume the ParsedFile objects this module produces.

Design decisions:
- A file with a syntax error must NOT crash the whole scan. Real
  codebases sometimes contain a broken/WIP file, a Python 2 file, or a
  file with an unusual encoding. We catch SyntaxError (and a few other
  parse-time failures) per-file, record the error, and move on --
  exactly what the brief asks for ("parsing errors gracefully
  handled... syntax error wali files skip/log ho").
- We use `tokenize.open()` instead of a plain `open()` to read source.
  tokenize.open() auto-detects the file's declared encoding (the
  "# -*- coding: ... -*-" PEP 263 comment), which a plain open() with a
  hardcoded utf-8 guess would get wrong on some real-world files.
- ParsedFile keeps the source lines (not just the tree) because later
  phases (the HTML reporter especially) need to show a snippet of the
  actual offending line next to each finding -- re-reading the file
  from disk at report time would be wasteful and fragile if the file
  changed/moved.
- parse_project() returns ALL files (successes and failures) in one
  list rather than silently dropping failures, so failures are visible
  in the final report/log rather than disappearing without a trace.
"""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, field
from typing import List, Optional

from scanner.input_handler.file_walker import ScannedFile


@dataclass
class ParsedFile:
    """Result of attempting to parse a single ScannedFile.

    Exactly one of (tree) or (parse_error) will be meaningfully set:
    - Success: tree is a real ast.Module, parse_error is None.
    - Failure: tree is None, parse_error describes what went wrong.

    `source_lines` is always populated when the file could at least be
    READ (even if it failed to parse) so later tooling can still show
    the raw content for debugging.
    """

    scanned_file: ScannedFile
    tree: Optional[ast.Module] = None
    source_code: str = ""
    source_lines: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    @property
    def relative_path(self):
        return self.scanned_file.relative_path

    @property
    def ok(self) -> bool:
        """True if this file parsed successfully and has a usable tree."""
        return self.tree is not None and self.parse_error is None

    def line(self, lineno: int) -> str:
        """Return the raw source text of a given 1-indexed line number.
        Used by later phases (rules/reporter) to show a code snippet
        next to a finding. Returns "" if the line number is out of range
        rather than raising -- a reporter shouldn't crash over this."""
        idx = lineno - 1
        if 0 <= idx < len(self.source_lines):
            return self.source_lines[idx]
        return ""

    def __repr__(self) -> str:
        status = "ok" if self.ok else f"FAILED ({self.parse_error})"
        return f"ParsedFile({self.relative_path}, {status})"


def parse_file(scanned_file: ScannedFile) -> ParsedFile:
    """Read and AST-parse a single file. Never raises -- all failure
    modes (unreadable file, syntax error, null bytes, encoding issues)
    are captured into ParsedFile.parse_error instead.
    """
    path = scanned_file.absolute_path

    # Step 1: read the file, respecting its declared encoding.
    try:
        with tokenize.open(path) as f:
            source_code = f.read()
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        # SyntaxError here covers tokenize.open() failing to even detect
        # a valid encoding declaration -- that's a read-time failure,
        # not a parse-time one, but the effect is the same: we can't
        # proceed with this file.
        return ParsedFile(
            scanned_file=scanned_file,
            parse_error=f"Could not read file: {exc}",
        )

    source_lines = source_code.splitlines()

    # Step 2: parse into an AST.
    try:
        tree = ast.parse(source_code, filename=str(scanned_file.relative_path))
    except SyntaxError as exc:
        return ParsedFile(
            scanned_file=scanned_file,
            source_code=source_code,
            source_lines=source_lines,
            parse_error=f"SyntaxError at line {exc.lineno}: {exc.msg}",
        )
    except ValueError as exc:
        # ast.parse can raise ValueError for things like source code
        # containing null bytes -- distinct from a "normal" SyntaxError
        # but still just a bad file we should skip, not crash on.
        return ParsedFile(
            scanned_file=scanned_file,
            source_code=source_code,
            source_lines=source_lines,
            parse_error=f"Could not parse: {exc}",
        )

    return ParsedFile(
        scanned_file=scanned_file,
        tree=tree,
        source_code=source_code,
        source_lines=source_lines,
    )


def parse_project(scanned_files: List[ScannedFile]) -> List[ParsedFile]:
    """Parse every file found by Phase 1's walk_project(). Returns one
    ParsedFile per input file, successes and failures both included --
    callers can filter with [p for p in results if p.ok].
    """
    return [parse_file(f) for f in scanned_files]


def parse_summary(parsed_files: List[ParsedFile]) -> str:
    """Human-readable one-line-per-failure summary, used by the CLI/logs
    so parse failures are visible instead of silently swallowed."""
    total = len(parsed_files)
    failed = [p for p in parsed_files if not p.ok]
    lines = [f"Parsed {total - len(failed)}/{total} file(s) successfully."]
    if failed:
        lines.append(f"{len(failed)} file(s) failed to parse:")
        for p in failed:
            lines.append(f"  {p.relative_path}: {p.parse_error}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    from scanner.input_handler.file_walker import walk_project

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanned = walk_project(target)
    results = parse_project(scanned)
    print(parse_summary(results))