#!/usr/bin/env sh
# honmoon Claude Code plugin — hook dispatcher.
#
# Forwards the hook event JSON (read on stdin) to `honmoon hook`, which scans
# for secrets + PII and writes the hook verdict JSON to stdout. If the honmoon
# binary is not installed, this is a deliberate no-op (exit 0, no output): the
# plugin degrades gracefully so tool calls / prompts proceed rather than error
# on every hook, and the honmoon proxy remains the enforcement backstop.
#
# Override the binary location with HONMOON_BIN (absolute path or command name).
set -eu

bin="${HONMOON_BIN:-honmoon}"

if ! command -v "$bin" >/dev/null 2>&1; then
  exit 0
fi

# `exec` inherits this script's stdin/stdout, so the payload streams straight
# through to `honmoon hook` and its verdict streams straight back out.
exec "$bin" hook
