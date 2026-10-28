"""Fail the release gate for absent, failed, or silently skipped regressions.

Consumes only locally generated pytest JUnit; does not inspect or run samples.
"""
import sys
import xml.etree.ElementTree as ET


def check(path, minimum=1):
    if type(minimum) is not int or minimum < 1:
        raise ValueError("Positive minimum test count required")
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    if not cases or any(case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error")):
        raise ValueError("Release requires executed, passing tests with zero skips")
    # A collection/import error can be a suite child without a testcase.
    if list(root.iter("error")) or list(root.iter("failure")):
        raise ValueError("Release test report contains errors")
    if len(cases) < minimum:
        raise ValueError("Release test report does not cover the minimum regression inventory")
    return len(cases)


if __name__ == "__main__":
    try:
        minimum = int(sys.argv[2]) if len(sys.argv)>2 else 1
        print(f"Release gate: {check(sys.argv[1], minimum)} tests, zero skips/failures/errors")
    except (ValueError, OSError, ET.ParseError, IndexError) as exc:
        print(f"Release gate rejected: {exc}", file=sys.stderr)
        raise SystemExit(1)
