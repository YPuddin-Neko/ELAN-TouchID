#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
exec > >(tee -a native-credential-plugin-test.log) 2>&1
RIGHT=io.github.hackintosh-tools.elan-unlock.test
if [[ "$(id -u)" == 0 ]]; then echo '请从当前登录账户运行此脚本。';exit 1;fi
ELAN_USER_HOME="$(/usr/bin/python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
BACKUP="$ELAN_USER_HOME/Desktop/ELAN 指纹适配/备份/ELAN-native-credential-probe-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$(dirname "$BACKUP")"
mkdir "$BACKUP"
/usr/bin/security authorizationdb read "$RIGHT" > "$BACKUP/test-right-before.plist"
/usr/bin/python3 - "$BACKUP/test-right-before.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1],'rb') as f: rule=plistlib.load(f)
assert rule.get('class')=='evaluate-mechanisms'
assert rule.get('mechanisms')==['ELANFingerprintAuth:fingerprint','builtin:authenticate,privileged']
PY
for STANDARD_RIGHT in system.login.console system.login.screensaver system.privilege.admin; do
    /usr/bin/security authorizationdb read "$STANDARD_RIGHT" > "$BACKUP/$STANDARD_RIGHT.before.plist"
done
printf '原生指纹凭据接口测试\n\n'
printf '本次更新已安装的 ELAN 测试插件，查询一个空的系统认证会话。\n'
printf '测试没有指纹窗口，无需按手指；独立测试授权项会自动恢复。\n'
printf '请输入本机登录密码以更新测试插件，不需要重启。\n\n'
sudo -v
sudo bash ./install-auth-prototype.command --update
RESTORE=0
restore_right() {
    if [[ "$RESTORE" == 1 ]]; then
        sudo /usr/bin/security authorizationdb write "$RIGHT" < "$BACKUP/test-right-before.plist"
        RESTORE=0
    fi
}
trap restore_right EXIT
RESTORE=1
sudo /usr/bin/security authorizationdb write "$RIGHT" < ./elan-credential-probe-right.plist
TEST_STATUS=0
./elan-auth-probe --credential-request || TEST_STATUS=$?
restore_right
/usr/bin/security authorizationdb read "$RIGHT" > "$BACKUP/test-right-after.plist"
for STANDARD_RIGHT in system.login.console system.login.screensaver system.privilege.admin; do
    /usr/bin/security authorizationdb read "$STANDARD_RIGHT" > "$BACKUP/$STANDARD_RIGHT.after.plist"
done
/usr/bin/python3 - "$BACKUP" <<'PY'
import pathlib,plistlib,sys
root=pathlib.Path(sys.argv[1])
for name in ['test-right','system.login.console','system.login.screensaver','system.privilege.admin']:
    separator='-' if name=='test-right' else '.'
    before=plistlib.loads((root/(name+separator+'before.plist')).read_bytes())
    after=plistlib.loads((root/(name+separator+'after.plist')).read_bytes())
    for rule in (before,after):
        for key in ('created','modified'):rule.pop(key,None)
    assert before==after,name+' changed'
print('AUTHORIZATION_RULES_RESTORED')
PY
/usr/bin/log show --last 3m --style compact --predicate 'eventMessage BEGINSWITH "ElanNativeProbe:"' > native-credential-plugin-system.log
if [[ "$TEST_STATUS" != 0 ]]; then
    printf '\n测试返回异常，授权项已恢复。请保留此窗口。\n';exit "$TEST_STATUS"
fi
printf '\nNATIVE_CREDENTIAL_PROBE_COMPLETE\n测试结束，未授予认证，授权项已恢复。可以关闭此窗口。\n'
