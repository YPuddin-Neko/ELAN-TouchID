# ELAN Fingerprint 采集与匹配库

本目录实现 ELAN USB 指纹传感器（`04f3:0c1a` 144 × 64、`04f3:0c6e` 150 × 52）的用户态 USB 通信、图像背景消减、`elanpress` SIFT 局部特征提取/几何一致性比对，以及指纹模板目录序列化。

## 模块说明

- `vendor/libusb/`：内置的用户态 USB 通信库。
- `vendor/elanpress/`：基于 `libfprint`（`elanpress`）的 SIFT 特征点提取与几何一致性匹配算法。
- `src/ElanFingerprintCatalog.*`：多指纹身份目录、UUID 与模板序列化管理。
- `src/ElanFingerprintEnrollment.*`：多阶段指纹样本采集与质量控制状态机。
- `src/ElanFingerprintMatcher.*`：指纹特征比对与最佳匹配记录检索。
- `src/ElanFingerprintSession.*`：指纹目录事务提交与通知发布。

## 独立调试工具编译（可选）

如需单独运行合成图像自检或命令行硬件探针，可使用以下命令构建：

```sh
# 编译命令行自检并验证合成图像特征匹配与模板序列化
ARCH=x86_64 bash build.sh --app-only
./build/ELANFingerprint.app/Contents/MacOS/ElanUnlock --self-test

# 编译独立命令行硬件探针
ARCH=x86_64 bash scripts/build-diagnostic.sh
./build/diagnostic-x86_64/elan-diagnostic --probe
```

## 上游与许可证

- [filip-rs/libfprint](https://github.com/filip-rs/libfprint/tree/elanpress)：图像处理和特征匹配，© Filip Spanne，LGPL-2.1-or-later。
- [casimir-engineering/elan-fp-fix](https://github.com/casimir-engineering/elan-fp-fix)：传感器状态读取与图像轮询参考。
- [libfprint elan](https://github.com/filip-rs/libfprint/blob/elanpress/libfprint/drivers/elan.c)：`0c1a` 通信与图像布局参考，© Igor Filatov，LGPL-2.1-or-later。
- [libusb/libusb](https://github.com/libusb/libusb)：用户态 USB 通信库，LGPL-2.1-or-later。

本目录代码遵循 [LGPL-2.1-or-later](LICENSE) 许可证，上游归属详见 [UPSTREAM.md](UPSTREAM.md)。
