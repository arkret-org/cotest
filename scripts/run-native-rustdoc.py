#!/usr/bin/env python3
"""Transparent rustdoc wrapper for complete workspace shard accounting."""

import os
import sys

from native_workspace_execution import run_rustdoc


if __name__ == '__main__':
    try:
        sys.exit(run_rustdoc(sys.argv[1:], os.environ.copy()))
    except (OSError, RuntimeError, ValueError, KeyError):
        print('workspace rustdoc provenance failed', file=sys.stderr)
        sys.exit(1)
