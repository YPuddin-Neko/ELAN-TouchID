# ELAN-TouchID

为无 T2 芯片的 Intel 黑苹果实现 ELAN USB 指纹传感器（`04f3:0c1a`）的 macOS 原生触控 ID 驱动栈，打通 `BiometricKit`、`AppleCredentialManager`、`LocalAuthentication` 与 `loginwindow`。

## 电脑配置

### TM1963

| 规格     | 详细信息                                                   |
| -------- | ---------------------------------------------------------- |
| 电脑型号 | 小米笔记本电脑Pro 15.6'' (MX250)                           |
| 处理器   | 英特尔 酷睿 i7-10510U 处理器                               |
| 内存     | 16GB 三星 DDR4 2666MHz                                     |
| 硬盘     | 英特尔 SSD 660P 系列                                       |
| 集成显卡 | 英特尔 超高清显卡 620                                      |
| 显示器   | LQ156M1JW01 SHP14C3 1920x1080 344x194mm 15.5-inch          |
| 声卡     | 瑞昱 ALC256 (节点: 69)                                     |
| 无线网卡 | 英特尔 Wireless-AC 9462                                    |
| 触控板   | ELAN2303                                                   |
| 指纹模块 | ELAN USB Fingerprint (`04f3:0c1a`，144 × 64，固件 `0x0142`) |
| 操作系统 | macOS Sequoia 15.8.1 (Build `24H32`，Intel `x86_64`)       |
| 引导环境 | OpenCore + `Lilu.kext`                                     |

无 T2 芯片的 Intel 平台不含硬件安全隔区（SEP），不支持 FileVault 预启动解锁，冷启动首次登录需输入密码。

## 实现机制

- **`BiometricKit` 虚拟设备与内核凭证桥接（`ELANNativeProbeAutomaticSettings.kext`）**：
  基于 Lilu 在内核态识别 `TouchIDPasswordExtension` 与 `coreauthd` 进程，重定向 `BiometricKit` XPC 服务连接并切换平台生物识别可用性缓存；通过 `IOUserClient` 与内核 `AppleCredentialManager` 同步生物识别可用状态、已注册身份目录及实时匹配结果，使系统原生「触控 ID 与密码」设置面板、`密码.app`、Safari 自动填充及 `LocalAuthentication` 直接调用该传感器。
- **USB 图像采集与 SIFT 特征匹配服务（`ELANSensorService`）**：
  通过 `libusb` 驱动 `04f3:0c1a` 传感器完成 144 × 64 原始帧读取与背景消减，使用 `elanpress` SIFT 局部特征点提取与几何一致性算法完成多阶段指纹录入与比对，实现 `BiometricKitXpcProtocol` 的录入、身份管理、受保护配置读写与 `coreauthd` 匹配回调。
- **内核态凭证捕获与 `IOHIKeyboard` 锁屏解锁**：
  在系统设置校验管理员密码时从 `AppleCredentialManager` 捕获并经 OpenDirectory 核验解锁凭证；锁屏状态下完成指纹特征匹配后，通过内核 `IOHIKeyboard::dispatchKeyboardEvent` 直接向 `IOHIDSystem` 派发硬件级按键事件，由 `loginwindow` 完成屏幕、登录钥匙串与系统密钥袋解锁。

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
