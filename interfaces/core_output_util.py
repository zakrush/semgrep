"""Utilities to convert some of the output of semgrep-core further
"""

from pathlib import Path
from semgrep.output_from_core import Error
from semgrep.error import SemgrepCoreError

CoreErrorType = NewType("CoreErrorType", str)

def to_semgrep_error(e: Error) -> SemgrepCoreError:
    reported_rule_id = e.rule_id if e.rule_id else ''

    error_type = CoreErrorType(e.error_type);

    location = e.location
    start = CoreLocation.from_core(location.start)
    end = CoreLocation.from_core(location.end)
    path = Path(location.path)

    # severity -> level
    severity = e.severity.kind
    if severity == "warning":
        level_str = "WARN"
    elif severity == "error":
        level_str = "ERROR"
    else:  # bug
        level = "UNKNOWN"

    # TODO benchmarking code relies on error code value right now
    # See https://semgrep.dev/docs/cli-usage/ for meaning of codes
    if error_type == CoreErrorType(
        "Syntax error"
    ) or error_type == CoreErrorType("Lexical error"):
        code = 3
        reported_rule_id = None  # Rule id not important for parse errors
    else:
        code = 2

    # TODO legacy support for live editor pattern parse highlighting
    spans = None
    if e.yaml_path is not None:
        rev_yaml_path = e.yaml_path[::-1]
        spans = tuple([LegacySpan(start, end, rev_yaml_path)])  # type: ignore

    return SemgrepCoreError(
        code,
        level,
        error_type,
        reported_rule_id,
        path,
        start,
        end,
        e.message,
        spans,
        e.details,
    )
