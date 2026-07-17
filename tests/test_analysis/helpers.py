"""
helpers.py
----------
Shared helper for the Phase 3 analysis unit tests: builds a ParsedFile
directly from a source-code string, without needing to write a real
file to disk first. Keeps each test focused on one small code snippet.
"""

import ast
from pathlib import Path

from scanner.input_handler.file_walker import ScannedFile
from scanner.parser.ast_parser import ParsedFile


def parse_source(code: str, filename: str = "test_sample.py") -> ParsedFile:
    """Parse a source string into a ParsedFile, as if it had come out
    of the Phase 1/2 pipeline (walk_project -> parse_project)."""
    scanned = ScannedFile(absolute_path=Path(filename), relative_path=Path(filename))
    tree = ast.parse(code)
    return ParsedFile(
        scanned_file=scanned,
        tree=tree,
        source_code=code,
        source_lines=code.splitlines(),
    )


def get_function(parsed_file: ParsedFile, name: str):
    """Return the first FunctionDef/AsyncFunctionDef with the given name
    from a ParsedFile's tree. Raises if not found -- a test that can't
    find its own sample function should fail loudly, not silently skip."""
    for node in ast.walk(parsed_file.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise ValueError(f"No function named '{name}' found in parsed source")