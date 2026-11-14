#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"
probe="./native-auth-02/auth-x86_64/elan-auth-probe"
run_test() {
    local name="$1" expected="$2"
    read -r -p '准备好后按回车打开认证窗口：' _ || return 1
    "$probe" --request 2>&1 | tee "native-capture-$name.log"
    local result=${PIPESTATUS[0]}
    printf '%s\n' "$result" > "native-capture-$name.exit"
    if [[ "$result" != "$expected" ]]; then
        printf '本次测试已停止，退出码：%s。请保留窗口。\n' "$result"
        return 1
    fi
}
echo '1/3：用没有录入过的另一根手指。窗口提示轻放后按一次；看到“不匹配”后点取消。'
if run_test other 2; then
    echo '2/3：用已录入的手指，指腹中心轻放。匹配成功后窗口应自行关闭。'
    if run_test center 0; then
        echo '3/3：仍用已录入的手指，向指尖方向轻移约1毫米。匹配成功后窗口应自行关闭。'
        run_test shifted 0
    fi
fi
echo '本轮结束。请回到对话说明看到的结果。'
read -r -p '按回车关闭此终端：' _
