#!/bin/bash
cd "$(dirname "$0")"
set -o pipefail
./elan-diagnostic 2>&1 | tee test-02.log
status=$?
printf '%s\n' "$status" > test-02.exit
printf '\n测试已结束。可以关闭这个窗口。\n'
read -r
