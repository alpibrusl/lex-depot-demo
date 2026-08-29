#!/bin/sh
# The demo, revealed a line at a time. See demo/record.sh for why.
#
# Act 3's money lines get their own, slower beat. They are the argument — an
# invoice for a shed that was held, a payment for the one that happened, and
# the spread the intermediary keeps — and at the default rate a room reads the
# next line before it has finished the last. Everything else stays brisk;
# slowing the whole run to suit four lines would only make it long.
set -e
cd "$(dirname "$0")/.."
lex run --allow-effects io,sql,fs_write,time,crypto,approval,env src/scenario.lex main \
  | grep -v '^null$' \
  | while IFS= read -r l; do
      printf '%s\n' "$l"
      case "$l" in
        ACT*)                          sleep 0.9 ;;
        *"aggregator invoices"*)       sleep 1.1 ;;
        *"meter says"*)                sleep 1.1 ;;
        *"over-claim"*)                sleep 1.6 ;;
        *"DSO pays the aggregator"*)   sleep 1.1 ;;
        *"aggregator pays the depot"*) sleep 1.1 ;;
        *"kept on the gap"*)           sleep 1.8 ;;
        *"energy bill"*)               sleep 0.5 ;;
        *"flexibility payment"*)       sleep 0.5 ;;
        "")                            sleep 0.35 ;;
        *)                             sleep 0.12 ;;
      esac
    done
