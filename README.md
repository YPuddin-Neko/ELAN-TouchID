# ELAN-TouchID

ELAN USB 指纹传感器（`04f3:0c1a`）的 macOS 触控 ID 驱动，接入「系统设置 → 触控 ID 与密码」、`LocalAuthentication` 与 `loginwindow`。

## 功能

- **系统设置管理**：在「系统设置 → 触控 ID 与密码」中添加、重命名和删除指纹（最多 3 枚）。
- **功能开关**：支持「使用触控 ID 解锁 Mac」「将触控 ID 用于 Apple Pay」「将触控 ID 用于 iTunes Store、App Store 和 Apple Books」「将触控 ID 用于自动填充密码」「将触控 ID 用于快速用户切换」。
- **系统与应用认证**：支持 `密码.app`、Safari 密码自动填充及系统 `LocalAuthentication` 触控 ID 验证。
- **锁屏解锁**：锁屏状态下按压指纹完成验证并解锁桌面、登录钥匙串与系统密钥袋。

## 适用环境

- **指纹硬件**：ELAN USB 指纹模块（`VID: 0x04f3`，`PID: 0x0c1a`，144 × 64）
- **操作系统**：macOS Sequoia 15.8.1（Build `24H32`，Intel `x86_64`）
- **引导环境**：OpenCore + `Lilu.kext`

无 T2 芯片的 Intel 平台不含硬件安全隔区（SEP），不支持 FileVault 预启动解锁，冷启动首次登录需输入密码。

## 组件

1. **`ELANNativeProbeAutomaticSettings.kext`**
   放入 `EFI/OC/Kexts/` 并在 OpenCore `config.plist` 中排在 `Lilu.kext` 之后启用。负责桥接系统设置与 `coreauthd` 的 `BiometricKit` 连接、校验凭证上下文及提交锁屏解锁按键。
2. **`ELANSensorService`**
   由用户级 `LaunchAgent`（`~/Library/LaunchAgents/io.github.hackintosh-tools.elan-usb.plist`）随登录启动。负责 USB 图像采集、特征提取与指纹比对。

## 编译构建

需要 macOS 与 Xcode Command Line Tools，构建内核扩展另需 `MacKernelSDK` 与 `Lilu.kext` 头文件资源。

```sh
# 1. 编译后台传感器服务 ELANSensorService
python3 -B references/authplugin-research/build-native-provider.py \
    --sensor-service-only --out /tmp/elan-service-build

# 2. 编译内核扩展 ELANNativeProbeAutomaticSettings.kext
python3 -B references/authplugin-research/kernel-provider/build.py \
    --sdk /path/to/MacKernelSDK \
    --lilu /path/to/Lilu.kext/Contents/Resources \
    --automatic-settings \
    --enrollment-service /tmp/elan-service-build/ELANSensorService \
    --service-home /Users/<username> \
    --out /tmp/elan-kernel-build
```

## 目录结构

- `references/authplugin-research/kernel-provider/`：`ELANNativeProbeAutomaticSettings.kext` 内核扩展源码。
- `references/authplugin-research/usb-sensor/`：`ELANSensorService` 后台服务与 `BiometricKit` 协议实现，详见 [后台服务说明](references/authplugin-research/usb-sensor/README.md)。
- `references/authplugin-research/agent-integration-candidate/`：内核符号绑定、进程识别与协议门面模块。
- `elan-fingerprint-macos/`：底层 USB 采集（`libusb`）、`elanpress` SIFT 特征匹配算法与指纹模板序列化库，详见 [算法与采集库说明](elan-fingerprint-macos/README.md)。
- `references/libfprint-elan.*`：`libfprint` ELAN 协议参考实现。

## 开源许可

底层采集与匹配库基于 [s17765152890-gif/elan-fingerprint-macos](https://github.com/s17765152890-gif/elan-fingerprint-macos) 及 `libfprint`（`elanpress`）适配开发，遵循 [LGPL-2.1-or-later](elan-fingerprint-macos/LICENSE) 许可证；上游归属详见 [UPSTREAM.md](elan-fingerprint-macos/UPSTREAM.md)。
