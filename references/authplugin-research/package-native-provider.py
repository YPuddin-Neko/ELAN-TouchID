#!/usr/bin/env python3
import ast
import importlib.util
import json
import plistlib
import shutil
from pathlib import Path

source = Path(__file__).resolve().parent
build = source.parents[1] / 'build/research'
package = build / 'native-provider-package-06'
package.mkdir()
spec = importlib.util.spec_from_file_location('deployment', source / 'native-provider-deployment.py')
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


def copy(origin, destination):
    if origin.is_dir():
        shutil.copytree(origin, destination)
    else:
        shutil.copy2(origin, destination)


for name in deployment.ASSETS[:4]:
    copy(build / 'native-provider-06' / name, package / name)
for name in ['native-provider-deployment.py', 'native-session-lifecycle.py',
             'native-settings-diagnostic.py', 'native-settings-result.py', 'native-kernel-identity.py']:
    shutil.copy2(source / name, package / name)
for version in ['05', '06']:
    destination = package / 'payload' / ('native-kernel-probe-' + version)
    destination.mkdir(parents=True)
    copy(build / ('native-kernel-probe-' + version) / 'ELANNativeProbe.kext', destination / 'ELANNativeProbe.kext')
    if version == '06':
        shutil.copy2(build / 'native-kernel-probe-06/kernel-identity.json', destination / 'kernel-identity.json')
        deployment.require_kernel_artifact(package)
        shutil.copy2(build / 'native-kernel-probe-06/elan-native-probe', destination / 'elan-native-probe')
        shutil.copy2(source / 'kernel-provider/manage-efi.py', destination / 'manage-efi.py')
previous = package / 'previous'
previous.mkdir()
for name in deployment.PREVIOUS_ASSETS:
    origin = build / ('native-provider-fix-03' if name in ['ELANNativeProvider.app', 'native-provider-deployment.py'] else 'native-provider-package-05') / name
    copy(origin, previous / name)
deployment.verify_signatures(package)
deployment.verify_signatures(previous)
files = deployment.asset_bytes(package)
for relative in files:
    if relative.endswith('.py'):
        ast.parse(files[relative], filename=relative)
for relative, version in [('ELANNativeProvider.app', deployment.VERSION), ('previous/ELANNativeProvider.app', deployment.PREVIOUS_VERSION),
                          ('payload/native-kernel-probe-06/ELANNativeProbe.kext', deployment.VERSION), ('payload/native-kernel-probe-05/ELANNativeProbe.kext', deployment.PREVIOUS_VERSION)]:
    info = plistlib.loads((package / relative / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleVersion') != version:
        raise RuntimeError('Wrong package version: ' + relative)
for filename, action, installed in [
    ('1-升级到0.4.0.command', 'install', False),
    ('2-重启后认证与原生设置测试.command', 'test-settings', True),
    ('3-清理临时测试.command', 'cleanup', True),
    ('4-撤回到0.3.0.command', 'rollback', True),
    ('5-清理未完成的安装暂存.command', 'cleanup-staged', False),
    ('6-会话退出与恢复测试.command', 'test-session', True),
    ('7-启用后台指纹服务.command', 'enable-background', True),
    ('8-停止后台指纹服务.command', 'disable-background', True),
    ('9-查看后台服务状态.command', 'background-status', True),
    ('10-原生设置短诊断.command', 'diagnose-settings', True),
]:
    location = "'/Library/ELANFingerprintNativeTest/native-provider-deployment.py'" if installed else '\"$package_dir/native-provider-deployment.py\"'
    text = '#!/bin/zsh\npackage_dir="${0:A:h}"\n'
    privilege = '' if action == 'background-status' else '/usr/bin/sudo '
    text += f'{privilege}/usr/bin/python3 -I -B {location} {action}\n'
    text += 'result=$?\nprint "执行结果：$result"\nread "?请回到聊天核对结果。按回车关闭。"\nexit $result\n'
    target = package / filename
    target.write_text(text)
    target.chmod(0o755)
(package / '说明.txt').write_text("""ELAN 原生认证 0.4.0 测试包

用于从已安装的 0.3.0 升级。仅支持当前小米的 macOS 15.8.1（24H32）、UID501 和指定测试 U 盘。
安装目录：/Library/ELANFingerprintNativeTest
备份和日志：桌面/ELAN 指纹适配/备份、日志

升级前核对现有配套程序和 U 盘驱动，检查临时服务连接，并备份整套 0.3.0。
经同意安装并核对后，手动重启一次，再运行第 2 项。
测试会临时接管当前用户的生物识别服务，修改该用户的 coreauthd 和 Touch ID 设置扩展的内存状态；清理时退出对应进程。
服务仅在当前桌面会话中处理认证；切换或退出用户、认证进程变化时停止采集并清理本次连接。
先检查原装认证窗口的取消、错误手指、正确手指及轻移，再检查原生设置的列表、取消录入、两阶段录入、改名、重新打开和删除新测试指纹。
保留原有指纹。若某一步失败，测试停止并清理临时服务。
系统设置全过程仍需实机确认。锁屏、开机登录、钥匙串授权及其他应用认证不属于这一脚本的已验证项目。
本轮先测试指纹列表、录入、改名和删除，请保持其他开关不变。“解锁 Mac”仍待接入；开启它会返回不支持。
0.4.0 的原生指纹项可保存识别配置，兼容读取此前的数据格式。撤回 0.3.0 时使用保留的原始指纹项。

撤回恢复 U 盘驱动和整套 0.3.0 配套程序，保留指纹钥匙串；若已启动 0.4.0，需要手动重启才能加载旧驱动。
第 5 项仅清理升级前未完成的安装暂存；升级已生效时使用第 4 项。
第 6 项在原生认证和钥匙串授权完成后运行 15 分钟，检查切换用户和会话恢复；按 Control-C 可提前结束。后台读取不弹出钥匙串授权窗口，连续失败三次后停止重试。
睡眠时停止当前采集并释放设备，唤醒完成后重新连接；睡前未完成的认证需要重新发起。测试期间可手动睡眠再唤醒。
第 7 项在系统 LaunchDaemons 中安装后台服务，随后自动运行；登录当前用户后接入指纹，切换或退出用户时清理，睡眠后重新连接。先完成原生认证、设置和会话测试，再启用。
第 8 项停止后台服务并移除自动启动配置；第 9 项查看状态，无需管理员密码。运行其他测试或撤回时，也会先停止后台服务。
后台管理程序异常退出时，配套程序通过控制连接断开退出，系统再启动管理程序进行恢复。检测到配置、钥匙串或连续运行错误时停止服务，需处理错误后重新启用。
第 10 项启动临时原生服务，通过现有代理接入设置，仍可能临时修改认证和设置扩展的内存状态；结束时执行清理。只观察界面，不重复四项认证，不录入或删除指纹、不更改开关，也不启用连接缓存恢复。运行前会停止后台服务并取消自动启动；结束后需要时用第 7 项重新启用。诊断及清理结果以脱敏 JSON 输出；输入 cancel 或按 Control-C 可取消并清理。
脚本不自动重启，不修改 USB、蓝牙或启动参数。
""")
record = {'package': str(package), 'version': deployment.VERSION, 'previous_version': deployment.PREVIOUS_VERSION,
          'asset_files': len(files), 'signatures_verified': True, 'source_syntax_verified': True,
          'kernel_identity_manifest': 'payload/' + deployment.KERNEL_PACKAGE + '/kernel-identity.json',
          'installed': False, 'deployment_authorized': False, 'live_settings_tested': False,
          'test_actions': ['authentication-regression', 'native-settings-lifecycle', 'bounded-session-lifecycle', 'managed-background-service',
                           'native-settings-diagnostic'],
          'user_session_guard_integrated': True, 'session_transition_runtime_verified': False,
          'bounded_session_supervisor_prepared': True, 'session_supervisor_live_tested': False,
          'power_transition_guard_prepared': True, 'sleep_wake_runtime_verified': False,
          'persistent_startup_prepared': True, 'persistent_startup_installed': False,
          'protected_configuration_interface_prepared': True, 'catalog_schema': 2,
          'protected_configuration_live_settings_verified': False, 'native_unlock_toggle_supported': False,
          'real_keychain_persistence_across_provider_restart_tested': False}
(package / 'package.json').write_text(json.dumps(record, indent=2) + '\n')
(package / 'background-service.plist').write_bytes(plistlib.dumps(deployment.background_plist()))
print(json.dumps(record, indent=2))
