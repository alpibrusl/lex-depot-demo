#!/bin/sh
# Run the demo exactly as the recording shows it.
#
# The `grep -v` drops the interpreter's echo of main's return value — that is
# `lex run` reporting Unit, not output from the demo, and it reads as an error
# to anyone watching.
set -e
cd "$(dirname "$0")/.."
lex run --allow-effects io,sql,fs_write,time,crypto,approval,env src/scenario.lex main | grep -v '^null$'
