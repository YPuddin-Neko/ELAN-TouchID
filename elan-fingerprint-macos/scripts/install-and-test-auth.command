#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
ACTION="${1:---install}"
if [[ "$ACTION" == --update ]]; then LOG=update.log;TEST_LOG=auth-window-02.log;else LOG=install.log;TEST_LOG=auth-window-01.log;fi
echo "准备 ELAN 独立认证测试插件。请输入这台电脑的登录密码；终端不会显示输入的字符。"
sudo bash ./install-auth-prototype.command "$ACTION" | tee "$LOG"
echo "插件已准备好。接下来打开系统认证测试窗口；请先点“取消”，暂时不要按指纹。"
read -r -p "按回车打开认证窗口：" _
set +e
./elan-auth-probe --request | tee "$TEST_LOG"
result=${PIPESTATUS[0]}
set -e
echo "测试程序已结束，退出码：$result。请回到对话告知看到的窗口。"
read -r -p "按回车关闭此终端：" _
