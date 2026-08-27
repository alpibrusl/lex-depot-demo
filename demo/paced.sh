#!/bin/sh
# The demo, revealed a line at a time. See demo/record.sh for why.
set -e
cd "$(dirname "$0")/.."
lex run --allow-effects io,sql,fs_write,time,crypto,approval src/scenario.lex main \
  | grep -v '^null$' \
  | while IFS= read -r l; do
      printf '%s\n' "$l"
      case "$l" in
        ACT*) sleep 0.9 ;;
        "")   sleep 0.35 ;;
        *)    sleep 0.12 ;;
      esac
    done
