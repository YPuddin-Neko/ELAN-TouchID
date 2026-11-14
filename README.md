# ELAN-TouchID

ELAN USB 指纹模块的 macOS 适配与原生认证接口研究，主要面向 `04f3:0c1a`。

## 源码布局

- `elan-fingerprint-macos/`：用户态采集、匹配、录入界面与认证插件，构建说明见其 [README](elan-fingerprint-macos/README.md)。
- `references/authplugin-research/`：原生 provider、会话管理、内核接口、测试与构建研究代码。
- `references/libfprint-elan.*`：ELAN 协议参考源码。

这里发布的是源码研究快照，不是可直接安装的驱动发行版。原生 provider 代码版本为 0.4.0，安装后重启及实际系统认证验证仍未完成；不宣称提供 Secure Enclave、Apple Pay 或 FileVault 预启动能力。

## 公开范围与本机构建

保持目录相对布局，以便研究构建脚本引用共享源码。构建输出、现场日志、EFI/NVRAM、指纹图像及模板、钥匙串数据、备份均未纳入仓库。8 个含本机账户路径或 EFI 标识的部署/恢复脚本保留在本机，不公开。

因此原生打包、部署、恢复流程及依赖 `native-provider-deployment.py` / `manage-efi.py` 的测试不能在此公开快照中完整运行。不要直接使用此快照修改系统认证或 EFI。用户名、目标 UID 和平台版本相关假设尚需在通用部署流程中解决。

可单独运行不依赖部署模块的会话生命周期测试：

```sh
python3 references/authplugin-research/test_native_session_lifecycle.py
```

## 来源与许可证

`elan-fingerprint-macos/` 基于 [s17765152890-gif/elan-fingerprint-macos](https://github.com/s17765152890-gif/elan-fingerprint-macos)，导入基础提交为 `57d85fd`；本仓库以源码快照保留本地适配，不导入嵌套 Git 元数据。其许可证见 [LICENSE](elan-fingerprint-macos/LICENSE)，依赖归属见 [UPSTREAM.md](elan-fingerprint-macos/UPSTREAM.md)，各第三方文件保留原许可证及作者声明。`references/libfprint-elan.*` 保留 libfprint 的 LGPL 声明。
