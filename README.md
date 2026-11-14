# ELAN-TouchID

ELAN USB 指纹模块的 macOS 适配与原生认证接口研究，主要面向 `04f3:0c1a`。

## 源码布局

- `elan-fingerprint-macos/`：用户态采集、匹配、录入界面与认证插件，构建说明见其 [README](elan-fingerprint-macos/README.md)。
- `references/authplugin-research/`：原生 provider、会话管理、内核接口、测试与构建研究代码。
- `references/libfprint-elan.*`：ELAN 协议参考源码。

这里发布的是源码研究快照，不是可直接安装的驱动发行版。原生 provider 以 0.4.0 为研究基线；原生设置页的完整录入与认证流程尚未完成，不宣称提供 Secure Enclave、Apple Pay 或 FileVault 预启动能力。

## 公开范围与本机构建

保持目录相对布局，以便研究构建脚本引用共享源码。构建输出、现场日志、EFI/NVRAM、指纹图像及模板、钥匙串数据、备份均未纳入仓库。8 个含本机账户路径或 EFI 标识的部署/恢复脚本保留在本机，不公开。

因此原生打包、部署、恢复流程及依赖 `native-provider-deployment.py` / `manage-efi.py` 的测试不能在此公开快照中完整运行。不要直接使用此快照修改系统认证或 EFI。用户名、目标 UID 和平台版本相关假设尚需在通用部署流程中解决。

## 当前修复与离线验证

- provider 的空 accessory 保护及设备 flags 修正。
- 单次匹配共用采集截止时间；晚到的帧、特征提取及匹配结果不再提交成功。同步 USB 调用或锁等待仍可能超过截止时间，不能视为硬实时超时。
- 可执行映射识别支持 thin/FAT Mach-O slice，并保留只读诊断计数。
- 日志结果解析器只保留有限协议字段，不复制原始日志或把退出成功当成功能验证。

macOS 配合 Xcode 命令行工具可运行：

```sh
python3 -B references/authplugin-research/match-deadline-tests/run.py
(cd references/authplugin-research && python3 -B -m unittest test_native_settings_result)
xcrun clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined references/authplugin-research/test-native-executable-slice.cpp -o /tmp/elan-slice-test
/tmp/elan-slice-test
```

匹配截止时间测试包含 native、x86_64、ASan/UBSan 三个变体，每个 27 例；Apple silicon 的 x86_64 变体需要 Rosetta。这些是抽取生产源码并使用合成数据的回归，不访问传感器或认证服务，也不是硬件及设置界面的端到端验证。完整部署相关测试仍依赖上述未公开的机器脚本。

未完成的内核写入/恢复实验、历史候选和机器专用交付包保留在本地，不包含在本次公开修复中。

## 来源与许可证

`elan-fingerprint-macos/` 基于 [s17765152890-gif/elan-fingerprint-macos](https://github.com/s17765152890-gif/elan-fingerprint-macos)，导入基础提交为 `57d85fd`；本仓库以源码快照保留本地适配，不导入嵌套 Git 元数据。其许可证见 [LICENSE](elan-fingerprint-macos/LICENSE)，依赖归属见 [UPSTREAM.md](elan-fingerprint-macos/UPSTREAM.md)，各第三方文件保留原许可证及作者声明。`references/libfprint-elan.*` 保留 libfprint 的 LGPL 声明。
