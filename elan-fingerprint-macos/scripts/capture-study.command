#!/bin/bash
set -o pipefail
cd "$(dirname "$0")"
"$HOME/Applications/ELANFingerprint.app/Contents/MacOS/ElanUnlock" --capture-study 2>&1 | tee capture-study-01.log
status=$?
printf '%s\n' "$status" > capture-study-01.exit
printf '\n测试已结束，可以关闭这个窗口。\n'
read -r
exit "$status"
