#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
exec > >(tee -a native-service-reset.log) 2>&1
PLIST=/System/Library/LaunchDaemons/com.apple.biometrickitd.plist
SERVICE=system/com.apple.biometrickitd
printf '清理指纹测试请求\n\n'
printf '苹果指纹服务正在重试刚才的硬件查询。此操作重新加载原服务，清空未完成请求。\n'
printf '不修改系统文件、认证规则或 EFI，也不需要重启。\n'
printf '请输入本机登录密码；输入时不会显示字符。\n\n'
sudo -v
SERVICE_INFO=$(/bin/launchctl print "$SERVICE")
case "$SERVICE_INFO" in
    *"path = $PLIST"*) ;;
    *) printf '服务路径不符，未执行。\n'; exit 1 ;;
esac
UNLOADED=0
restore_service() {
    if [ "$UNLOADED" -eq 1 ]; then
        printf '重新加载苹果原服务……\n'
        sudo /bin/launchctl bootstrap system "$PLIST" || true
    fi
}
trap restore_service EXIT
sudo /bin/launchctl bootout system "$PLIST"
UNLOADED=1
sudo /bin/launchctl bootstrap system "$PLIST"
UNLOADED=0
/bin/launchctl print "$SERVICE"
printf '\nSERVICE_RESET_COMPLETE\n清理完成，可以关闭此终端窗口。\n'
