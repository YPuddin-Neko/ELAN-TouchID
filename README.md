# ELAN-TouchID

面向无 T2 芯片 Intel 黑苹果的 ELAN USB 指纹模块（`04f3:0c1a`，144 × 64，固件 `0x0142`）macOS 原生「触控 ID 与密码」接入与认证驱动实现，已在 macOS Sequoia 15.8.1（`24H32`，x86_64）实机验证。

## 功能与实测状态

- **系统设置原生录入与管理**：支持在「系统设置 → 触控 ID 与密码」中直接新建、重命名、删除指纹（最多 3 枚），指纹目录与用户配置持久化保存在 `~/Library/Application Support/ELANFingerprint/`（权限 `0600`），开机登录不弹出钥匙串授权提示，重启后已录入指纹持久保留。
- **触控 ID 功能开关**：支持开启与持久化「使用触控 ID 解锁 Mac」「将触控 ID 用于 Apple Pay」「将触控 ID 用于 iTunes Store、App Store 和 Apple Books」「将触控 ID 用于自动填充密码」「将触控 ID 用于快速用户切换」。
- **系统级生物认证（`密码.app` / 自动填充）**：内核将当前登录会话（UID 501）下 `TouchIDPasswordExtension` 与 `coreauthd` 的 `BiometricKit` XPC 连接定向至用户态服务 `ELANSensorService`（`io.hackmac.elan.touchid`），并在指纹匹配后向内核 `AppleCredentialManager` 提交验证结果，支持 `密码.app` 启动解锁与密码自动填充。
- **免辅助功能权限的锁屏解锁**：锁屏状态下由 `ELANSensorService` 完成真实 USB 指纹采集与局部特征匹配，匹配通过后经内核 `ELANEnrollmentPolicyClient`（`ElanDispatchUnlockKeystrokes`）直接调用 `IOHIKeyboard::dispatchKeyboardEvent` 向 `IOHIDSystem` 分发硬件级按键与回车，无需手动授予 macOS「辅助功能（Accessibility / TCC）」权限即可开箱解锁屏幕、登录钥匙串与系统密钥袋。

详细组件说明见 [ELAN USB 设备服务与原生接入说明](references/authplugin-research/usb-sensor/README.md)。

## 架构与硬件限制

系统由配对运行的内核扩展与普通用户 LaunchAgent 组成：

1. **`ELANNativeProbeAutomaticSettings.kext`（基于 Lilu 的内核扩展）**
   - 在 macOS 15.8.1（`24H32`）上按进程签名与审计会话识别 `TouchIDPasswordExtension` 和 `coreauthd`（UID 501），完成 `BiometricKit` 平台可用性缓存在线切换与私有 XPC 服务名重定向。
   - 通过 `ELANEnrollmentPolicyClient` 校验系统设置传入的 `AppleCredentialManager` 密码认证上下文（`ElanCheckEnrollment`），同步已录入身份目录（`ElanSyncProviderCatalog`）与实时匹配结果（`ElanSubmitDirectMatch`）。
   - 在用户在「触控 ID 与密码」验证登录密码时，从 `AppleCredentialManager` 凭据属性自动捕获并经 OpenDirectory 校验后同步锁屏凭据（`ElanCopyEnrollmentPassphrase`），并提供内核级 `IOHIKeyboard` 锁屏按键派发接口（`ElanDispatchUnlockKeystrokes`）。
2. **`ELANSensorService`（普通用户 LaunchAgent，`io.github.hackintosh-tools.elan-usb`）**
   - 监听 `io.hackmac.elan.touchid`，通过用户态 `libusb` 驱动 `04f3:0c1a` 传感器完成图像采集、背景消减与 SIFT 风格几何一致性特征比对。
   - 实现 `BiometricKitXpcProtocol` 录入、进度反馈、身份目录查询、受保护配置读写与 `coreauthd` 匹配回调。

**硬件与平台边界**：
- 无 T2 芯片的 Intel 平台不存在物理 Secure Enclave（SEP），不支持 FileVault 预启动解锁与开机首次冷启动无密码登录（开机首次登录仍需输入密码以解锁系统卷与初始密钥袋）。
- 锁屏状态下，为保证 `loginwindow` 完整解锁 `login.keychain-db` 与系统数据保护密钥袋（Keybag），指纹特征比对通过后由内核通过 `IOHIKeyboard` 自动填入密码并确认，锁屏界面会短暂显示密码圆点随后进入桌面。
- 内核符号偏移与进程映射签名针对 macOS 15.8.1（Build `24H32`，Darwin `24.6.0`）构建。

## 源码布局

- `elan-fingerprint-macos/`：用户态 USB 采集、elanpress SIFT 特征匹配、指纹目录模型与独立图形工具，见其 [README](elan-fingerprint-macos/README.md)。
- `references/authplugin-research/usb-sensor/`：`ELANSensorService` 用户态服务、系统设置录入与 `coreauthd` 匹配后端、直接内核策略客户端及单元测试。
- `references/authplugin-research/kernel-provider/`：`ELANNativeProbeAutomaticSettings.kext` 内核扩展、进程发现与页表策略、`AppleCredentialManager` 桥接、`IOHIKeyboard` 按键分发与主机态状态机测试。
- `references/authplugin-research/agent-integration-candidate/`：内核运行时绑定、启动期进程观测与协议门面组件。
- `references/libfprint-elan.*`：ELAN 协议参考源码。

构建产物、现场日志、EFI/NVRAM 镜像、指纹模板与密码凭据均已通过 `.gitignore` 排除，不纳入版本库。

## 构建与离线验证

需要 macOS 与 Xcode Command Line Tools。构建内核扩展另需 `MacKernelSDK` 与 `Lilu.kext` 头文件资源。

```sh
# 1. 构建用户态服务 ELANSensorService
python3 -B references/authplugin-research/build-native-provider.py \
    --sensor-service-only --out /tmp/elan-service-build

# 2. 构建配对的内核扩展 ELANNativeProbeAutomaticSettings.kext（自动运行 26 项内核状态机测试）
python3 -B references/authplugin-research/kernel-provider/build.py \
    --sdk /path/to/MacKernelSDK \
    --lilu /path/to/Lilu.kext/Contents/Resources \
    --automatic-settings \
    --enrollment-service /tmp/elan-service-build/ELANSensorService \
    --service-home /Users/<username> \
    --out /tmp/elan-kernel-build
```

运行离线回归测试：

```sh
# USB 传感器配置、内核策略通道与对端审计令牌测试
sh references/authplugin-research/usb-sensor/build.sh /path/to/MacKernelSDK /tmp/elan-usb-build

# 采集截止时间与协议结果回归测试
python3 -B references/authplugin-research/match-deadline-tests/run.py
(cd references/authplugin-research && python3 -B -m unittest test_native_settings_result test_native_current_update test_native_current_update_package)
xcrun clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
    references/authplugin-research/test-native-executable-slice.cpp -o /tmp/elan-slice-test && /tmp/elan-slice-test
```

## 来源与许可证

`elan-fingerprint-macos/` 基于 [s17765152890-gif/elan-fingerprint-macos](https://github.com/s17765152890-gif/elan-fingerprint-macos)（基础提交 `57d85fd`）适配开发；许可证见 [LICENSE](elan-fingerprint-macos/LICENSE)，上游归属见 [UPSTREAM.md](elan-fingerprint-macos/UPSTREAM.md)。`references/libfprint-elan.*` 保留 libfprint 的 LGPL-2.1-or-later 声明。
