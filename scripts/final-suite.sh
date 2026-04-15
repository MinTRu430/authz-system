#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_ROOT="${RESULT_ROOT:-$ROOT/results/final/$STAMP}"

mkdir -p "$RESULT_ROOT"

echo "[*] final suite result root -> $RESULT_ROOT"

RESULT_DIR="$RESULT_ROOT/functional" STAMP="$STAMP" "$ROOT/scripts/final-functional.sh"
RESULT_DIR="$RESULT_ROOT/bench" STAMP="$STAMP" "$ROOT/scripts/final-bench.sh"

{
  echo "Final suite timestamp: $STAMP"
  echo
  echo "Functional summary:"
  echo "$RESULT_ROOT/functional/summary.csv"
  echo
  echo "Benchmark summary:"
  echo "$RESULT_ROOT/bench/bench_summary.csv"
  echo
  echo "Key artifacts:"
  find "$RESULT_ROOT" -maxdepth 2 -type f | sort
} > "$RESULT_ROOT/README.txt"

echo "[+] final suite complete"
echo "[+] see $RESULT_ROOT/README.txt"
