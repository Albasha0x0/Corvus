# Corvus

[English](README.md) · **简体中文** · [日本語](README.ja.md)

**面向 AI 代理的逆向工程与安全分析。** Corvus 是一个 MCP 服务器，用于读取、跟踪、比较和修补已编译的程序：.NET 程序集，以及原生
PE、ELF 和 Mach-O 二进制文件。单个自包含二进制文件，无需安装运行时，不上传任何内容；默认情况下不执行它读取的任何内容。

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/stargazers)

> [!NOTE]
> 本文译自 [README.md](README.md)；内容不一致时以英文版为准。Corvus 仍在积极开发中。工具、参数和输出可能在版本之间变化；
> 破坏性变更列在[发行说明](docs/release-notes.md)中。请在 [issues](https://github.com/Albasha0x0/Corvus/issues) 中报告问题。

[快速开始](#快速开始) · [工作原理](#工作原理) · [可分析的内容](#可分析的内容) ·
[示例](#示例) · [为什么选择 Corvus](#为什么选择-corvus) · [文档](#文档)

## 快速开始

**Windows**（PowerShell）：

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

**Linux / macOS：**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

安装程序会对照发行版的 `SHA256SUMS` 校验下载内容；当 `gh` 已登录时，还会校验其签名的构建来源证明（没有 `gh` 时会提示
"provenance not checked"），然后在找到的 MCP 客户端中注册 Corvus。作为插件（服务器和技能；需要 .NET 10 SDK）：在 Claude Code
中运行 `/plugin install corvus --marketplace Albasha0x0/Corvus`；在 Codex 中运行 `codex plugin marketplace add Albasha0x0/Corvus`，
然后在 `/plugins` 中选择 `corvus`（[安装](docs/installation.md#claude-code-and-codex-plugins)）。作为只读根文件系统的容器：
`docker run -i --rm --read-only --tmpfs /tmp -v "$PWD:/work:ro" ghcr.io/albasha0x0/corvus`
（[安装](docs/installation.md#container-image)）。重启客户端后提问：

> Load app.dll with Corvus and explain how it builds its export file. Cite the methods you read.

在终端中：`corvus decompile_member --load app.dll member=Ns.Type::Method`（[命令行](docs/cli.md)）。

## 工作原理

代理通过 MCP 调用 Corvus。结果有大小上限且结构化：每个列表都可分页，每个错误都指明下一步，较长的结果会保存供
`read_result` 读取。代理沿着调用和引用继续分析，并可以修补并保存副本。

Corvus 自带的引擎分析原生代码（x86、x64、ARM32、ARM64）；安装了 IDA 或 Ghidra 时，它们可作为可选的反编译器。它们的数据库和输出会被保留，
因此之后对同一二进制文件的调用很快。

## 可分析的内容

| 目标 | 得到的结果 | 依赖 |
|---|---|---|
| .NET 程序集 | C# 反编译、IL、引用、调用图、构建比较、C# 和 IL 修补、保存 | 无 |
| 原生二进制文件（PE、ELF、Mach-O） | 函数、反汇编、CFG、交叉引用、值、RTTI、PDB 类型、相似函数 | 无 |
| 原生伪代码 | 反编译、引擎类型、栈帧、脚本、模拟执行、伪代码搜索 | IDA 9（idalib）或 Ghidra 12 |
| WebAssembly | 模块和组件、反汇编、反编译代码 | 无 |
| NativeAOT 和 ReadyToRun | 方法名、MethodTable、字符串、预编译代码 | 无 |
| Unity Il2Cpp 构建 | 来自元数据的方法名和地址、字符串字面量、序列化资源字段、IDA / Ghidra 脚本、C++ 绑定 | 无 |
| 原生修补 | 名称、注释、字节补丁、汇编补丁（x86 和 x64）、修补后的副本，并延续到新构建 | 无 |
| 容器 | 单文件包、NuGet、APK、IPA、ASAR、Unity WebGL、归档、安装程序（MSI、NSIS、Inno Setup、WiX Burn）、冻结的 Python（PyInstaller、py2exe、cx_Freeze、Nuitka onefile；Nuitka standalone 只描述，不提取）、固件映像和文件系统、磁盘映像（ISO/UDF、VHD/VHDX、Apple .dmg、NTFS、FAT、ext、HFS+、APFS）、编译后的资源目录（Assets.car）、Unreal pak 和 IoStore 容器、GameMaker 数据文件、Lua 和 LuaJIT 字节码、编译后的 AutoIt 脚本；CycloneDX SBOM、YARA-X 匹配 | 无 |
| 文档和脚本 | Office VBA 和 Excel 4.0 宏、加密的 OOXML、PDF 动作和 JavaScript、OneNote、LNK；不运行即可去混淆的 PowerShell、批处理、VBScript 和 JavaScript | 无 |
| 安装前的软件包 | npm、PyPI、VS Code 扩展、浏览器扩展（CRX、XPI）：安装脚本、原生文件、可疑模式 | 无 |
| 网络捕获 | pcap 和 pcapng、TCP 流、HTTP/1 和 HTTP/2 对象、使用密钥日志解密的 TLS 1.2/1.3、JA3/JA4、DNS 和信标提示 | 无（仅其他 Wireshark 字段需要 TShark） |
| 语言和数据 | Go、Swift、Delphi 和 Free Pascal 元数据；Hermes 和 Ark 字节码；HarmonyOS 软件包；带源映射的 JavaScript 包；保存的网页及其脚本完整性哈希、导入映射和 meta CSP 检查；从嵌入描述符恢复的 protobuf 定义；恢复已删除行的 SQLite | 无 |
| Android 软件包 | 清单、资源、DEX、smali、Java（JADX）、JNI 绑定、通过 adb 连接的设备 | Java 需要 JADX，设备需要 adb |
| 崩溃转储 | Windows 小型转储（minidump）、Linux 和 macOS 核心转储、.NET 异常、调用栈、堆；崩溃文本 | 无 |
| 运行中的程序 | 只读进程检查；在 Windows、Linux 和 macOS 上带停止点、调用记录、代码覆盖率、快照和子进程的会话；Windows 上的活动跟踪（ETW）和控制台运行 | 会话需要 Frida 17.24.3 或更新的 17.x，默认关闭 |

完整列表：[功能](docs/features.md)和[工具参考](docs/tools.md)（165 个工具，15 个提示）。

## 示例

- **[反编译、重建、运行](docs/showcase/round-trip.md)：** 将程序集导出为 C# 项目，在警告视为错误的设置下构建，运行输出相同，并与原始程序进行比较度量。
- **[单文件应用的内部](docs/showcase/single-file.md)：** 不运行即可解包 .NET 单文件可执行文件，逐字节提取其程序集。
- **[SQLite 在哪里生成随机数](docs/showcase/sqlite-random.md)：** 将原生 SQLite 构建中的一个加密常量追溯到 `sqlite3_randomness`
  及其调用者，记录为证据包并重新验证。
- **[追溯 Json.NET 错误到代码](docs/showcase/json-reference-loop.md)：** 从消息 "Self referencing loop detected"
  追溯到决定它的设置和每个调用者，并重新验证证据。

示例和[指南](docs/guides/1-first-session.md)中的每一步都由测试检查。

## 为什么选择 Corvus

- **无需安装。** 原生分析、.NET 反编译、容器和转储均为内置功能。
- **快速。** 结果来自保存的索引和引擎数据库；预热后的调用在毫秒内响应。
- **为代理设计的大小。** 每个结果都符合令牌预算，支持分页和保存的结果。
- **不只读取，还能编辑。** 在内存中修补 .NET 和原生代码，审查差异，保存经过验证的副本，并将名称和补丁延续到下一个构建。
- **跨平台。** Windows、Linux（glibc 和 musl）和 macOS，x64 和 arm64：win-x64、win-arm64、linux-x64、
  linux-arm64、linux-musl-x64、linux-musl-arm64、osx-x64 和 osx-arm64。

支持的客户端：Claude Code、Claude Desktop、Cursor、Windsurf、VS Code、VS Code Insiders、VSCodium、Cline、Roo Code、
Kilo Code、Visual Studio、Codex、Gemini CLI、Qwen Code、GitHub Copilot CLI、OpenCode、Crush、Zed、LM Studio、
Amazon Q、Kiro、Antigravity、Devin、Command Code、Grok Build、OMP、Pi、Kimi Code、Qoder、Factory Droid、Trae、
CodeBuddy、Hermes 和 DeepSeek Harness。其他任何客户端：`corvus config`。

## 文档

[安装](docs/installation.md) · [配置](docs/configuration.md) · [功能](docs/features.md) · [工具参考](docs/tools.md) ·
[命令行](docs/cli.md) · [错误](docs/errors.md) · [故障排除](docs/troubleshooting.md) ·
[常见问题](docs/faq.md) · [发行说明](docs/release-notes.md) · [所有页面](docs/README.md)

指南：[第一次会话](docs/guides/1-first-session.md) · [解码和修补](docs/guides/2-decode-and-patch.md) ·
[新构建](docs/guides/3-new-build.md)。

## 负责任的使用

仅分析你拥有或被允许分析的软件。反编译、修补或重新分发第三方代码可能受其许可证和你所在地法律的限制。

[贡献](CONTRIBUTING.md) · [安全](SECURITY.md) · [Apache-2.0 许可证](LICENSE)

## Star 历史

<a href="https://www.star-history.com/#Albasha0x0/Corvus&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date&theme=dark" />
    <img alt="Corvus star history" src="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date" />
  </picture>
</a>
