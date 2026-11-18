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

- `src/`：指纹图像采集、多指纹身份目录、录入与匹配状态机。
- `vendor/`：`libusb`（macOS IOKit USB 后端）与 `elanpress`（SIFT 局部特征提取与几何一致性比对）。
- `references/authplugin-research/kernel-provider/`：`ELANNativeProbeAutomaticSettings.kext` 内核扩展源码。
- `references/authplugin-research/usb-sensor/`：`ELANSensorService` 后台服务与 `BiometricKit` 协议实现，详见 [后台服务说明](references/authplugin-research/usb-sensor/README.md)。
- `references/authplugin-research/agent-integration-candidate/`：内核符号绑定、进程识别与协议门面模块。

## 致谢与开源许可

- [s17765152890-gif/elan-fingerprint-macos](https://github.com/s17765152890-gif/elan-fingerprint-macos)：macOS 用户态 ELAN USB 传感器通信参考。
- [filip-rs/libfprint](https://github.com/filip-rs/libfprint/tree/elanpress)：`elanpress` SIFT 特征提取与匹配算法及 `04f3:0c1a` 协议参考。
- [libusb/libusb](https://github.com/libusb/libusb)：用户态跨平台 USB 通信库。

本项目遵循 [LGPL-2.1-or-later](LICENSE) 许可证。
