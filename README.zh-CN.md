# Corvus

[English](README.md)（原文，以其为准） · **简体中文** · [日本語](README.ja.md)

用于已编译程序逆向工程与安全分析的 MCP 服务器：.NET 程序集，以及原生 PE、ELF 和 Mach-O 二进制文件。

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)

- 单个自包含二进制文件。不上传任何内容；默认不执行它读取的任何内容。
- 工具和输出可能在版本之间变化；见[发行说明](docs/release-notes.md)。

## 快速开始

Windows（PowerShell）：

```powershell
irm https://github.com/Albasha0x0/Corvus/releases/latest/download/install.ps1 | iex
```

Linux 和 macOS：

```sh
curl -fsSL https://github.com/Albasha0x0/Corvus/releases/latest/download/install.sh | sh
```

安装程序校验下载内容，并向它找到的 MCP 客户端注册 Corvus。重启客户端后提问：

> 用 Corvus 加载 app.dll，说明它如何生成导出文件。引用你读过的方法。

- 插件、容器镜像和其他客户端：[安装](docs/installation.md)。
- 在终端中：`corvus decompile_member --load app.dll member=Ns.Type::Method`（[命令行](docs/cli.md)）。
- 构建：win-x64、win-arm64、linux-x64、linux-arm64、linux-musl-x64、linux-musl-arm64、osx-x64、osx-arm64。

## 工作原理

- 代理通过 MCP 调用 Corvus；每个结果都有上限，每个列表都分页，每个错误都指明下一步。
- Corvus 自带的引擎读取原生代码（x86、x64、ARM32、ARM64）；安装了 IDA 或 Ghidra 时可得到伪代码。
- 编辑在内存中进行；代理审阅差异后保存修补后的副本。

## 读取的内容

| 输入 | 显示 | 依赖 |
|---|---|---|
| .NET 程序集 | C#、IL、引用、调用图、补丁 | 无 |
| 原生 PE、ELF、Mach-O | 函数、反汇编、交叉引用、类型、补丁 | 无 |
| 原生伪代码 | 反编译的函数、引擎类型、脚本 | IDA 9 或 Ghidra 12 |
| NativeAOT、ReadyToRun、Il2Cpp | 方法名和地址、字符串 | 无 |
| WebAssembly | 模块、组件、反汇编 | 无 |
| 容器 | 单文件包、APK、IPA、安装程序、磁盘映像、固件 | 无 |
| 文档和脚本 | Office 宏、PDF 动作、反混淆的脚本 | 无 |
| 安装前的包 | npm、PyPI、RubyGems 和扩展包 | 无 |
| 网络捕获 | pcap 流、HTTP 对象、借助密钥日志解密的 TLS | 无 |
| Android | 清单、资源、DEX、Java | Java 需要 JADX，设备需要 adb |
| 崩溃转储 | 小型转储、核心转储、堆栈、.NET 堆 | 无 |
| 运行中的程序 | 停止点、调用记录、代码覆盖率 | Frida 17.24.3 至 17.24.x；默认关闭 |

全部 165 个工具和 15 个提示：[功能](docs/features.md)、[工具参考](docs/tools.md)。

指南：[第一次会话](docs/guides/1-first-session.md) · [解码与修补](docs/guides/2-decode-and-patch.md) ·
[新构建](docs/guides/3-new-build.md)。

## 文档

[安装](docs/installation.md) · [配置](docs/configuration.md) · [功能](docs/features.md) ·
[工具参考](docs/tools.md) · [命令行](docs/cli.md) · [错误](docs/errors.md) ·
[故障排除](docs/troubleshooting.md) · [常见问题](docs/faq.md) · [发行说明](docs/release-notes.md) ·
[全部页面](docs/README.md)

## 负责任地使用

只分析你拥有或获准分析的软件。许可证和当地法律可能限制反编译、修补和再分发。

[贡献](CONTRIBUTING.md) · [安全](SECURITY.md) · [Apache-2.0 许可证](LICENSE)