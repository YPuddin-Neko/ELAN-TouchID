#!/bin/bash
cd "$(dirname "$0")"
set -o pipefail
./elan-capture-compare 2>&1 | tee capture-compare-01.log
status=$?
printf '%s\n' "$status" > capture-compare-01.exit
printf '\n比较结束，可以关闭窗口。\n'
read -r
