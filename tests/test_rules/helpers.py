"""
helpers.py
----------
Shared helper for Phase 4 rule unit tests -- builds a ParsedFile
directly from a source-code string, same pattern as
tests/test_analysis/helpers.py.
"""

import ast
from pathlib import Path

from scanner.input_handler.file_walker import ScannedFile
from scanner.parser.ast_parser import ParsedFile


def parse_source(code: str, filename: str = "sample_module.py") -> ParsedFile:
    scanned = ScannedFile(absolute_path=Path(filename), relative_path=Path(filename))
    tree = ast.parse(code)
    return ParsedFile(
        scanned_file=scanned,
        tree=tree,
        source_code=code,
        source_lines=code.splitlines(),
    )