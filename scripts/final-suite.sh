#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_ROOT="${RESULT_ROOT:-$ROOT/results/final/$STAMP}"

mkdir -p "$RESULT_ROOT"

echo "[*] Корневой каталог результатов final suite -> $RESULT_ROOT"

RESULT_DIR="$RESULT_ROOT/functional" STAMP="$STAMP" "$ROOT/scripts/final-functional.sh"
RESULT_DIR="$RESULT_ROOT/bench" STAMP="$STAMP" "$ROOT/scripts/final-bench.sh"

{
  echo "Timestamp final suite: $STAMP"
  echo
  echo "Функциональная сводка:"
  echo "$RESULT_ROOT/functional/summary.csv"
  echo
  echo "Сводка benchmark:"
  echo "$RESULT_ROOT/bench/bench_summary.csv"
  echo
  echo "Ключевые artifacts:"
  find "$RESULT_ROOT" -maxdepth 2 -type f | sort
} > "$RESULT_ROOT/README.txt"

echo "[+] final suite завершен"
echo "[+] см. $RESULT_ROOT/README.txt"
