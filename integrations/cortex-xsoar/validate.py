#!/usr/bin/env python3
"""Checks the unified PortTorch.yml is actually loadable and internally
consistent before anyone uploads it to a live XSOAR.

Deliberately dependency-free (stock Python plus PyYAML) rather than
demisto-sdk: the point is that this runs anywhere, including on the
PortTorch host itself. It checks the things a broken BYOI upload actually
fails on - a YAML that will not parse, embedded Python that will not
compile, a command the code never handles, an argument the code never
reads, and metadata fields XSOAR requires.
"""

import ast
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
UNIFIED = HERE / "PortTorch.yml"
SOURCE = HERE / "PortTorch.py"

REQUIRED_TOP_LEVEL = ["commonfields", "name", "display", "category", "description", "configuration", "script"]
REQUIRED_SCRIPT = ["script", "type", "subtype", "dockerimage", "commands"]


def fail(problems: list, message: str) -> None:
    problems.append(message)


def main() -> int:
    problems: list = []

    integration = yaml.safe_load(UNIFIED.read_text())

    for key in REQUIRED_TOP_LEVEL:
        if key not in integration:
            fail(problems, f"missing top-level key: {key}")
    script_block = integration.get("script") or {}
    for key in REQUIRED_SCRIPT:
        if key not in script_block:
            fail(problems, f"missing script.{key}")

    code = script_block.get("script") or ""
    if code.strip() != SOURCE.read_text().strip():
        fail(problems, "PortTorch.yml is stale - re-run build_yml.py, its embedded code differs from PortTorch.py")
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        fail(problems, f"embedded Python does not compile: {exc}")
        tree = None

    # The image tag decides which Python actually compiles this code, and
    # getting it wrong fails before a single line runs. demisto/python3:latest
    # was last pushed in 2017 and is Python 3.3 - every f-string in this file
    # is a SyntaxError there, which is exactly how it failed in a real XSOAR.
    # demisto pins an exact build on every content integration; so does this.
    image = script_block.get("dockerimage") or ""
    if not re.fullmatch(r"demisto/[a-z0-9][a-z0-9._-]*:\d+(\.\d+)+", image):
        fail(problems, f"dockerimage must be a demisto image pinned to an exact version, got: {image or '(unset)'}")

    declared = [c["name"] for c in script_block.get("commands") or []]
    if len(declared) != len(set(declared)):
        fail(problems, "duplicate command names in the YAML")

    # Every declared command has to be reachable in main()'s dispatch, and
    # nothing may be dispatched that the YAML never declares - an
    # undeclared command is unreachable from the war room, and an
    # undispatched one fails at runtime with "not implemented".
    handled = set(re.findall(r'command == "([a-z0-9-]+)"', code))
    handled.discard("test-module")
    for name in declared:
        if name not in handled:
            fail(problems, f"command declared in YAML but not handled in main(): {name}")
    for name in sorted(handled - set(declared)):
        fail(problems, f"command handled in main() but not declared in YAML: {name}")

    # An argument the code never reads is a control that silently does
    # nothing - the failure mode a schema check would not catch.
    read_args = set(re.findall(r'args\.get\(\s*"([a-z0-9_]+)"', code)) | set(
        re.findall(r'args\[\s*"([a-z0-9_]+)"\s*\]', code)
    )
    for command in script_block.get("commands") or []:
        for argument in command.get("arguments") or []:
            if argument["name"] not in read_args:
                fail(problems, f"{command['name']}: argument '{argument['name']}' is never read by the code")
            if argument.get("auto") == "PREDEFINED" and not argument.get("predefined"):
                fail(problems, f"{command['name']}: argument '{argument['name']}' is PREDEFINED with no values")
        for output in command.get("outputs") or []:
            if not output.get("description"):
                fail(problems, f"{command['name']}: output {output.get('contextPath')} has no description")

    if tree is not None:
        functions = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        if "main" not in functions:
            fail(problems, "embedded code has no main()")

    if problems:
        print(f"{len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        f"ok: {UNIFIED.name} parses, {len(code.splitlines())} lines of Python compile, "
        f"{len(declared)} commands declared and all handled"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
