#!/usr/bin/env python3
"""Find IAM role ARNs in job env and GITHUB_ENV.

Does not print secret values. Writes JSON to stdout:
[{"arn": "...", "sources": ["env:NAME"]}]
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict

ROLE_ARN_RE = re.compile(
    r"arn:aws(?:-[a-z0-9]+)?:iam::\d{12}:role/[A-Za-z0-9+=,.@_\-/]+"
)

SKIP_ENV_NAMES = {
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_RUNTIME_URL",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
}


def find_arns(text: str) -> list[str]:
    if not text:
        return []
    return ROLE_ARN_RE.findall(text)


def main() -> int:
    found: dict[str, set[str]] = defaultdict(set)

    for name, value in os.environ.items():
        if name in SKIP_ENV_NAMES:
            continue
        for arn in find_arns(value or ""):
            found[arn].add(f"env:{name}")

    github_env = os.environ.get("GITHUB_ENV")
    if github_env and os.path.isfile(github_env):
        try:
            with open(github_env, encoding="utf-8", errors="replace") as handle:
                body = handle.read()
        except OSError:
            body = ""
        for arn in find_arns(body):
            found[arn].add("file:GITHUB_ENV")

    records = [
        {"arn": arn, "sources": sorted(sources)}
        for arn, sources in sorted(found.items())
    ]
    json.dump(records, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
