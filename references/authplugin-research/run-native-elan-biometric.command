#!/bin/bash
cd "$(dirname "$0")" || exit 1
/usr/bin/script -q "$PWD/live-study.log" "$PWD/ELANBiometricProbe.app/Contents/MacOS/ELANBiometricProbe" --live-study
printf '\n测试结束。按回车关闭此终端。\n'
read -r _
