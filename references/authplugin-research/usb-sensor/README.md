# ELANSensorService 后台传感器服务

本目录包含 `ELANSensorService` 用户态后台服务与 `ELANFingerprintUSB` 接口驱动，配合 `ELANNativeProbeAutomaticSettings.kext` 为 macOS 提供原生「触控 ID 与密码」支持。

## 工作机制

1. **服务启动与目录同步**
   - `ELANSensorService` 由 LaunchAgent（`io.github.hackintosh-tools.elan-usb.plist`）在用户登录后自动拉起并由 `KeepAlive` 常驻守护，监听 Mach 服务 `io.hackmac.elan.touchid`。
   - 启动时对服务二进制、LaunchAgent 配置及指纹数据文件自动施加 `UF_IMMUTABLE`（`uchg`）防误删保护，并通过 `DISPATCH_SOURCE_TYPE_VNODE` 监听 LaunchAgent 配置状态以在异常缺失时自动恢复。
   - 连接内核 `ELANEnrollmentPolicyClient`，激活当前会话生物识别可用性并同步已录入的指纹 UUID 列表。

2. **系统设置指纹录入与管理（`SettingsEnrollment.inc`）**
   - 实现 `BiometricKitXpcProtocol` 服务端接口，支持在「系统设置 → 触控 ID 与密码」中直接录入、重命名、删除指纹，以及读写触控 ID 功能开关。
   - 录入过程通过 USB 读取 `04f3:0c1a` 传感器图像并提取 SIFT 关键点模板，实时向系统设置返回采集进度与手指引导状态。

3. **系统生物认证与锁屏解锁**
   - 响应 `coreauthd` 发起的匹配请求（如 `密码.app`、Safari 自动填充等），比对通过后将匹配结果提交至内核 `AppleCredentialManager` 并返回 `BKIdentity`。
   - 锁屏状态下（`CGSSessionScreenIsLocked`），后台监听线程检测到已录入指纹按压后，通过内核 `IOHIKeyboard` 接口自动提交解锁按键。

## 编译命令

```sh
# 编译 ELANSensorService 与单元测试
sh build.sh /path/to/MacKernelSDK /tmp/elan-usb-build

# 编译配对的内核扩展
python3 -B ../kernel-provider/build.py \
    --sdk /path/to/MacKernelSDK \
    --lilu /path/to/Lilu.kext/Contents/Resources \
    --automatic-settings \
    --enrollment-service /tmp/elan-usb-build/ELANSensorService \
    --service-home /Users/<username> \
    --out /tmp/elan-kernel-build
```
