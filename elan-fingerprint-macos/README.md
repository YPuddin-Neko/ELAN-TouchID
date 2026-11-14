# ELAN Fingerprint Unlock for macOS

为 ELAN USB 指纹模块提供 macOS 用户态采集、指纹验证和锁屏解锁。本地分支正在适配小米 Pro CML 的 **04f3:0c1a（144 × 64，固件 0x0142）**，保留原有 04f3:0c6e 的通信方式。

真实 USB 指纹采集 → 图像处理与局部特征匹配 → 匹配成功 → 读取本机钥匙串密码 → 确认 loginwindow 的空安全密码框 → 输入密码并提交。

采集通信依据 elanpress 协议及 elan-fp-fix 的状态查询方式；使用 filip-rs/libfprint 最新 elanpress 的 SIFT 风格局部特征/几何一致性匹配，不是 NBIS，也不是仅检测触碰。

## 设备与验证状态

| 设备 | 当前状态 |
| --- | --- |
| 小米 Pro CML，04f3:0c1a，144 × 64 | 已在 macOS 15.8.1 上读取固件、连续采集图像并提取特征；已完成图形界面录入、钥匙串保存和匹配；用户反馈稍微移动指腹仍容易被拒绝，尚未验证锁屏解锁。 |
| ASUS M7400QC，04f3:0c6e，150 × 52 | 原项目报告完成录入、其他手指拒绝和锁屏解锁；本地分支没有这台设备，保留其状态查询顺序与旧模板读取。 |

0c1a 的前两轮快速按压测试同指接受为 1/3 和 0/3，其他手指均为 0/3；随后稳定中心位置的 24 帧平均对照改善了匹配，但日常使用仍反馈采集慢、偏移后容易拒绝。补录至 24 份后，在同一次按压中比较短等待单帧和 24 帧采集：单帧对原手指中心两次、前后轻移各一次的分数为 37、24、15、17，其他手指两次为 2、3；原平均方式分别为 45、45、19、14 和 3、3。两种方式在这 6 次测试中判断一致，单帧取得图像约需 0.28 秒，原方式约 3.24 秒。

当前 0c1a 改为检测到触碰后至少等待 200 毫秒，再取一帧；保留全部图像高度、现有模板和阈值 12。录入先取得两次相互匹配的样本，再要求后续样本能匹配上已录入的区域。实际应用中的短采集、系统指纹授权和锁屏仍需验证。

## 小米适配

- 从设备读取尺寸和固件，支持 0c1a 的图像读取顺序；0c6e 仍先查询状态再读图。
- 背景与模板按实际尺寸保存，模板包含设备 PID；继续读取原项目的 0c6e 旧模板。
- 0c1a 可保留已有的 8 份样本，继续补充至 24 份，分方向覆盖指腹；新增样本必须与已有区域匹配，匹配阈值仍为 12。小米已保存 24 份样本，但用户仍反馈采集慢、移动后容易不匹配。
- 增加“验证指纹”，可以在保存登录密码和授权辅助功能之前测试录入结果。
- 当前使用用户态 libusb，不安装内核扩展，不需要为应用更新重启电脑。USB 端口需要先在 EFI 中开放。

## 安装和使用

构建本分支应用，复制到应用程序目录后启动。上游 Releases 不包含这里的 0c1a 适配。启动后：

1. 移开手指，点击“录入 / 补充指纹”，全程使用同一根手指，轻放后等到松开提示再抬起。0c1a 先录入中心位置的 8 份样本，再按提示向左、右、前、后逐步轻移，共 24 份；已有指纹时选择“补充范围”即可保留旧样本继续录入。录满 8 份后逐次保存，可以停止并在下次继续。0c6e 保持 8 份样本。录入后先点“验证指纹”，分别测试指腹中心、稍微偏移的位置和其他手指。
2. 在应用的安全文本框输入当前用户的 macOS 登录密码并保存。应用用 OpenDirectory 在本机验证后，存入当前用户钥匙串。
3. 在系统设置 → 隐私与安全性 → 辅助功能中授权此应用，再点击启用。钥匙串提示应由用户自行确认。
4. 按 Control + Command + Q 锁屏，点一下密码框，松开后轻触录入的手指。

关闭窗口后保留菜单栏指纹图标，无 Dock 图标。菜单可以停止监听或退出。没有自动安装启动项。

## 限制与数据处理

- 仅打开 ELAN USB 04f3:0c1a 和 04f3:0c6e；0c1a 的识别率与锁屏流程仍在实测。
- 密码与模板保存在本机钥匙串，发布包不含任何模板或密码；没有联网代码或遥测。
- 匹配成功后才读取密码；重复检查锁屏状态、loginwindow 与空安全密码框。每次锁屏最多 4 次不匹配，最多尝试一次密码提交。
- macOS Secure Input、权限、输入焦点或固件差异都可能阻止自动输入。可以随时使用系统密码登录。
- 不是原生 Touch ID，不支持 Apple Touch ID API、Apple Pay、FileVault 预启动或冷启动首次登录，也不处理其他应用的密码弹窗。
- 登录钥匙串若锁定，自动读取可能失败。更新临时签名后可能需要移除旧辅助功能条目，再授权新版本。
- 本地钥匙串凭据和普通进程中的匹配无法提供 Secure Enclave 级别的隔离。同一用户下的恶意软件可能破坏此方案；它是便捷解锁实验。
- 本项目使用通用 Bundle ID/钥匙串服务名，不导入任何开发机器上的旧数据。

## 构建与检查

需要 macOS 和 Xcode Command Line Tools。无需 Homebrew 或额外安装依赖；libusb 与匹配库随源码提供。应用最低目标为 macOS 14。

```sh
# 为小米 Intel 黑苹果构建应用（Apple Silicon 主机上也可以交叉编译）
ARCH=x86_64 bash build.sh --app-only
# 构建应用及 DMG
ARCH=x86_64 bash build.sh
# 合成图匹配、两种尺寸的模板往返、旧模板读取与样本数量检查
./build/ELANFingerprint.app/Contents/MacOS/ElanUnlock --self-test
# 独立硬件诊断程序
ARCH=x86_64 bash scripts/build-diagnostic.sh
./build/diagnostic-x86_64/elan-diagnostic --probe
```

构建输出位于 `build/`，DMG 位于 `dist/`。在 Apple Silicon 上运行 x86_64 自检需要 Rosetta；也可把应用交给 Intel 目标机器运行自检。系统图标工具需要能正常访问图像文件的构建环境。

诊断程序不带参数时，会依次执行背景采集、8 次录入、3 次同指和 3 次其他手指比较。模板只保存在该进程内存，退出时释放；退出码 0 表示本轮同指 3/3、其他手指 0/3，2 表示匹配结果未达到该条件，1 表示未完成采集。合成图与模板自检不使用传感器；硬件验证需要用户实际按压。

`ElanUnlock --capture-study` 沿用钥匙串中的指纹，比较同一次按压的约 200 毫秒单帧、前后两段 9 帧平均和现用 21 帧平均。测试依次采集中心两次、轻微前后偏移各一次、未录入手指两次，记录用时、图像质量和匹配分数。图像与临时特征只在内存中处理，不修改已录入指纹，也不读取登录密码。退出码 0 仅表示采集流程完成，匹配结果需要按日志中的手指分组分析。

## 系统认证插件原型

`src/ElanAuthPlugin.m` 实现 `AuthorizationPluginCreate` 和 `SFAuthorizationPluginView`，用系统认证窗口承载指纹提示与密码回退。`ElanUnlock --auth-broker` 在已登录用户的会话中采集指纹，并读取该用户的钥匙串。服务使用内核提供的对端 audit token 检查 Apple SecurityAgent 的代码签名，只向通过检查的系统进程返回匹配后的账户凭据。插件确认服务所属用户后提交仅限认证机制使用的临时上下文，再交给 `builtin:authenticate,privileged` 检查密码。

当前构建包含独立测试授权项 `io.github.hackintosh-tools.elan-unlock.test`，没有接管锁屏、登录或管理员授权规则。它依赖已登录的用户会话，不支持 FileVault 预启动。小米的 `SecurityAgentHelper-x86_64` 已成功显示插件界面并处理取消，授权结果为 -60006；实际指纹授权尚未验证。这是系统认证窗口中的自定义视图，不是 Apple Touch ID。

测试备份统一放在用户桌面的 `ELAN 指纹适配/备份` 文件夹。插件更新脚本会在其中按时间保留旧版本。

```sh
ARCH=x86_64 bash scripts/build-auth-prototype.sh
# 只检查测试包和当前安装状态
bash build/auth-x86_64/install-auth-prototype.command --check
# 经确认后安装独立测试项；不会修改 system.login.* 或 system.privilege.admin
sudo bash build/auth-x86_64/install-auth-prototype.command --install
# 从桌面会话启动，先完成钥匙串访问授权；另一个终端请求测试授权
open -n ./build/ELANFingerprint.app --args --prepare-auth-broker
./build/auth-x86_64/elan-auth-probe --request
# 撤回独立测试项
sudo bash build/auth-x86_64/install-auth-prototype.command --remove
```

测试前先停止应用的锁屏监听和录入，避免同时占用 USB。服务没有安装启动项；结束对应的 `--prepare-auth-broker` 进程会移除本次创建的套接字。若在桌面终端直接运行 `--auth-broker`，可用 Control + C 停止。不要通过 SSH 会话启动正式测试服务：小米实测中，同一应用在桌面会话能读取登录钥匙串，SSH 会话返回 -25308。应用更新后可再次使用准备模式，让系统处理钥匙串许可。失败或取消不会直接授予测试权限；密码回退与指纹交接都必须经过后续的系统密码验证。安装脚本在同名插件或测试授权项已经存在时停止，避免覆盖已有配置。

`ElanUnlock --system-capabilities` 只查询 Apple 生物认证可用状态和指纹模板能否非交互读取，不读取登录密码。小米的桌面会话和 SSH 会话均返回生物认证不可用（错误 -6，类型 0）；当前适配不会使系统将 ELAN 注册为 Apple Touch ID。

## 原项目实测电脑

| 项目 | 规格 |
| --- | --- |
| 笔记本 | ASUS Vivobook Pro 14X OLED M7400QC |
| CPU | AMD Ryzen 7 5800H，8 核 16 线程 |
| 核显 | AMD Radeon Vega 8 / Renoir，系统报告 512 MB |
| 独显 | NVIDIA GeForce RTX 3050 Laptop GPU，4 GB GDDR6 |
| 内存 | 16 GB DDR4-3200 |
| 内屏 | 14 英寸 OLED，2880 × 1800，90 Hz |
| 外接屏 | Lenovo Y27q-30，2560 × 1440，144 Hz，当前由 AMD 输出 |
| 系统 | macOS Sequoia 15.8.1，x86_64，OpenCore |
| 指纹模块 | ELAN USB 04f3:0c6e，采集尺寸 150 × 52 |

硬件型号相同不保证固件和驱动行为一致。

## 上游和许可证

- 设计参考：[hackintosh-user/hack-touchid](https://github.com/hackintosh-user/hack-touchid)。本项目没有复制其认证守护进程；菜单、钥匙串和锁屏保护逻辑为独立实现。
- [filip-rs/libfprint](https://github.com/filip-rs/libfprint/tree/elanpress)：图像处理和特征匹配，© Filip Spanne，LGPL-2.1-or-later。
- [casimir-engineering/elan-fp-fix](https://github.com/casimir-engineering/elan-fp-fix)：传感器状态读取与图像轮询的参考。
- [libfprint elan](https://github.com/filip-rs/libfprint/blob/elanpress/libfprint/drivers/elan.c)：0c1a 通信与图像布局参考，© Igor Filatov，LGPL-2.1-or-later。
- [libusb/libusb](https://github.com/libusb/libusb)：用户态 USB，LGPL-2.1-or-later。

本项目以 LGPL-2.1-or-later 发布。完整 vendored libusb 源码、所用 matcher 源码、构建脚本与上游提交标识随仓库提供；保留原作者版权与许可证。可修改、替换库并重新链接构建。
