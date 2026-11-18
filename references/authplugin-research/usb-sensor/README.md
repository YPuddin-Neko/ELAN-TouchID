# ELAN USB 设备服务与原生系统接入

本目录实现 `ELANSensorService` 普通用户设备服务、`ELANFingerprintUSB` 接口匹配驱动，以及与 `ELANNativeProbeAutomaticSettings.kext` 配合的系统设置录入、`coreauthd` 生物认证与锁屏解锁后端。

## 组件职责

### 1. 普通用户设备服务（`ELANSensorService`）

- 由当前登录用户的 LaunchAgent（`io.github.hackintosh-tools.elan-usb.plist`）在 GUI 会话启动，注册 Mach 服务 `io.hackmac.elan.touchid`。
- 启动时向内核 `ELANEnrollmentPolicyClient` 发布当前会话监听器（`ElanPublishSettingsListener`），并将本地持久化的指纹身份目录同步至内核 `AppleCredentialManager`（`ElanSyncProviderCatalog`）。
- 指纹模板目录保存在 `~/Library/Application Support/ELANFingerprint/native-catalog-v2.plist`，触控 ID 开关受保护配置保存在同目录 `protected-config.plist`（文件权限均为 `0600`），避免登录或后台守护进程访问钥匙串时触发密码弹窗。

### 2. 系统设置录入与配置管理（`SettingsEnrollment.inc`）

- 对端连接通过 `audit_token_t`、代码签名与权限位区分系统设置扩展（`TouchIDPasswordExtension`）与 `coreauthd`（UID 501）。
- 支持 `BiometricKitXpcProtocol` 的完整设置生命周期：
  - `enroll:user:options:async:client:replyBlock:`：校验内核 `ElanCheckEnrollment` 授权上下文后启动 USB 采集，完成多阶段手指中心与边缘样本录入。
  - `match:options:async:client:replyBlock:`（`BKOptionMatchForExtendEnrollment`）：录入完成前的扩展采集验证。
  - `updateIdentity:` / `removeIdentity:` / `removeAllIdentitiesForUser:`：指纹重命名与删除，提交后实时同步内核目录并发送 `com.apple.BiometricKit.enrollmentChanged` 通知。
  - `getProtectedConfigurationForUser:` / `setProtectedConfiguration:user:options:async:client:replyBlock:`：管理「使用触控 ID 解锁 Mac」「Apple Pay」等开关，并在首次存在有效指纹时自动初始化 `BiometricKit_UseTouchIDForPurchase`、`WebKitPreferences.useTouchIDForAutofill` 与 `AMSDeviceBiometricsState`。

### 3. `coreauthd` 生物认证与锁屏解锁

- 当 `密码.app`、Safari 自动填充或系统认证请求触控 ID 时，`coreauthd`（UID 501）发起带 `BKOptionMatchForCredentialSet` / `BKOptionAuthWithCredentialSet` 的 `match:` 调用：
  - `ELANSensorService` 在采集期间通过 `statusMessage:` 回调手指按压/抬起状态（状态码 `63` / `64`）；
  - 匹配成功后调用 `ElanSubmitDirectMatch` 将匹配的身份 UUID 与认证上下文提交至内核 `AppleCredentialManager`，随后通过 `matchResult:details:client:` 返回 `BKIdentity`。
- 锁屏状态下（`CGSSessionScreenIsLocked`）：
  - 后台监听线程 `elanStartLockScreenWatcher` 在检测到手指按压并完成特征比对（`lockwatcher-hit`）后，调用 `IOPMAssertionDeclareUserActivity` 唤醒显示，并通过 `ElanDispatchUnlockKeystrokes` 请求内核 `IOHIKeyboard::dispatchKeyboardEvent` 直接在 `ApplePS2Keyboard` 工作循环上发送密码按键与回车，无需任何 `Accessibility`（TCC）权限即可完成 `loginwindow` 解锁。

## 构建与测试

```sh
# 运行描述符解析、内核策略接口与对端审计令牌测试，并构建 ELANFingerprintUSB.kext 与 ELANSensorService
sh build.sh /path/to/MacKernelSDK /tmp/elan-usb-build

# 构建配对的 0.6.2 自动设置内核扩展
python3 -B ../kernel-provider/build.py \
    --sdk /path/to/MacKernelSDK \
    --lilu /path/to/Lilu.kext/Contents/Resources \
    --automatic-settings \
    --enrollment-service /tmp/elan-usb-build/ELANSensorService \
    --service-home /Users/<username> \
    --out /tmp/elan-kernel-build
```
