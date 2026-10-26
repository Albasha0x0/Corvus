# Corvus

[English](README.md) · [简体中文](README.zh-CN.md) · **日本語**

**AI エージェントのためのリバースエンジニアリングとセキュリティ解析。** Corvus は、コンパイル済みプログラムを読み取り、トレースし、
比較し、パッチを当てる MCP サーバーです。対象は .NET アセンブリと、ネイティブの PE、ELF、Mach-O バイナリです。自己完結型の単一
バイナリで、ランタイムのインストールは不要、何もアップロードしません。既定では、読み取ったものを一切実行しません。

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/stargazers)

> [!NOTE]
> この文書は [README.md](README.md) の翻訳です。内容が異なる場合は英語版が優先されます。Corvus は活発に開発中です。ツール、
> パラメーター、出力はリリース間で変わることがあり、破壊的変更は[リリースノート](docs/release-notes.md)に記載されます。
> 不具合は [issues](https://github.com/Albasha0x0/Corvus/issues) で報告してください。

[クイックスタート](#クイックスタート) · [仕組み](#仕組み) · [解析できるもの](#解析できるもの) ·
[事例](#事例) · [Corvus を選ぶ理由](#corvus-を選ぶ理由) · [ドキュメント](#ドキュメント)

## クイックスタート

**Windows**（PowerShell）:

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

インストーラーは、ダウンロードをリリースの `SHA256SUMS` と照合し、`gh` にサインインしている場合は署名付きのビルド来歴も検証します
（`gh` がない場合は "provenance not checked" と表示）。その後、見つかった MCP クライアントに Corvus を登録します。プラグイン
（サーバーとスキル。.NET 10 SDK が必要）として: Claude Code では `/plugin install corvus --marketplace Albasha0x0/Corvus`、
Codex では `codex plugin marketplace add Albasha0x0/Corvus` を実行してから `/plugins` で `corvus` を選びます
（[インストール](docs/installation.md#claude-code-and-codex-plugins)）。読み取り専用ルートのコンテナーとして:
`docker run -i --rm --read-only --tmpfs /tmp -v "$PWD:/work:ro" ghcr.io/albasha0x0/corvus`
（[インストール](docs/installation.md#container-image)）。クライアントを再起動して、次のように尋ねます:

> Load app.dll with Corvus and explain how it builds its export file. Cite the methods you read.

ターミナルから: `corvus decompile_member --load app.dll member=Ns.Type::Method`（[コマンドライン](docs/cli.md)）。

## 仕組み

エージェントは MCP で Corvus を呼び出します。結果はサイズが制限され、構造化されています。すべての一覧はページングでき、すべての
エラーは次の手順を示し、長い結果は `read_result` のために保持されます。エージェントは呼び出しと参照をたどり、パッチを当てて
コピーを保存できます。

Corvus 自身のエンジンがネイティブコード（x86、x64、ARM32、ARM64）を解析します。IDA または Ghidra がインストールされていれば、
オプションの逆コンパイラーとして使えます。それらのデータベースと出力は保持されるため、同じバイナリへの以降の呼び出しは高速です。

## 解析できるもの

| 対象 | 得られるもの | 必要なもの |
|---|---|---|
| .NET アセンブリ | C# への逆コンパイル、IL、参照、呼び出しグラフ、ビルドの比較、C# と IL のパッチ、保存 | なし |
| ネイティブバイナリ（PE、ELF、Mach-O） | 関数、逆アセンブル、CFG、相互参照、値、RTTI、PDB の型、類似関数 | なし |
| ネイティブの疑似コード | 逆コンパイル、エンジンの型、フレーム、スクリプト、エミュレーション、疑似コード検索 | IDA 9（idalib）または Ghidra 12 |
| WebAssembly | モジュールとコンポーネント、逆アセンブル、逆コンパイルしたコード | なし |
| NativeAOT と ReadyToRun | メソッド名、MethodTable、文字列、プリコンパイル済みコード | なし |
| Unity Il2Cpp ビルド | メタデータからのメソッド名とアドレス、文字列リテラル、シリアル化されたアセットのフィールド、IDA / Ghidra スクリプト、C++ バインディング | なし |
| ネイティブのパッチ | 名前、コメント、バイトパッチ、アセンブリパッチ（x86 と x64）、パッチ済みコピー、新しいビルドへの引き継ぎ | なし |
| コンテナー | 単一ファイルバンドル、NuGet、APK、IPA、ASAR、Unity WebGL、アーカイブ、インストーラー（MSI、NSIS、Inno Setup、WiX Burn）、フリーズされた Python（PyInstaller、py2exe、cx_Freeze、Nuitka onefile。Nuitka standalone は説明のみで展開しない）、ファームウェアイメージとファイルシステム、ディスクイメージ（ISO/UDF、VHD/VHDX、Apple .dmg、NTFS、FAT、ext、HFS+、APFS）、コンパイル済みアセットカタログ（Assets.car）、Unreal pak と IoStore コンテナー、GameMaker データファイル、Lua と LuaJIT バイトコード、コンパイル済み AutoIt スクリプト。CycloneDX SBOM、YARA-X の一致 | なし |
| ドキュメントとスクリプト | Office VBA と Excel 4.0 マクロ、暗号化された OOXML、PDF のアクションと JavaScript、OneNote、LNK。実行せずに難読化を解除した PowerShell、バッチ、VBScript、JavaScript | なし |
| インストール前のパッケージ | npm、PyPI、VS Code 拡張機能、ブラウザー拡張機能（CRX、XPI）: インストールスクリプト、ネイティブファイル、疑わしいパターン | なし |
| ネットワークキャプチャ | pcap と pcapng、TCP ストリーム、HTTP/1 と HTTP/2 のオブジェクト、キーログで復号した TLS 1.2/1.3、JA3/JA4、DNS とビーコンのヒント | なし（その他の Wireshark フィールドのみ TShark） |
| 言語とデータ | Go、Swift、Delphi、Free Pascal のメタデータ。Hermes と Ark のバイトコード。HarmonyOS パッケージ。ソースマップ付きの JavaScript バンドル。保存された Web ページとそのスクリプトの整合性ハッシュ、インポートマップ、meta CSP の検査。埋め込み記述子から復元した protobuf 定義。削除された行を復元した SQLite | なし |
| Android パッケージ | マニフェスト、リソース、DEX、smali、Java（JADX）、JNI バインディング、adb 経由のデバイス | Java には JADX、デバイスには adb |
| クラッシュダンプ | Windows ミニダンプ、Linux と macOS のコアダンプ、.NET 例外、スタック、ヒープ。クラッシュテキスト | なし |
| 実行中のプログラム | 読み取り専用のプロセス検査。Windows、Linux、macOS での停止ポイント、呼び出しの記録、コードカバレッジ、スナップショット、子プロセスを備えたセッション。Windows でのアクティビティトレース（ETW）とコンソール実行 | セッションには Frida 17.24.3 以降の 17.x（既定でオフ） |

全一覧: [機能](docs/features.md)と[ツールリファレンス](docs/tools.md)（165 個のツール、15 個のプロンプト）。

## 事例

- **[逆コンパイル、再ビルド、実行](docs/showcase/round-trip.md):** アセンブリを C# プロジェクトとしてエクスポートし、警告を
  エラーとして扱う設定でビルドし、同じ出力で実行し、元のプログラムと比較して計測します。
- **[単一ファイルアプリの内部](docs/showcase/single-file.md):** .NET の単一ファイル実行可能ファイルを実行せずに展開し、その
  アセンブリをバイト単位で一致する形で取り出します。
- **[SQLite が乱数を作る場所](docs/showcase/sqlite-random.md):** ネイティブ SQLite ビルドの暗号定数を `sqlite3_randomness`
  とその呼び出し元までたどり、証拠バンドルとして記録して再検証します。
- **[Json.NET のエラーをコードまでたどる](docs/showcase/json-reference-loop.md):** "Self referencing loop detected"
  というメッセージから、それを決める設定とすべての呼び出し元までたどり、証拠を再検証します。

事例と[ガイド](docs/guides/1-first-session.md)の各手順はテストで検査されています。

## Corvus を選ぶ理由

- **インストール不要。** ネイティブ解析、.NET の逆コンパイル、コンテナー、ダンプは組み込みです。
- **高速。** 結果は保存済みのインデックスとエンジンのデータベースから返され、ウォーム状態の呼び出しはミリ秒で応答します。
- **エージェント向けのサイズ。** すべての結果はトークン予算に収まり、ページングと保持された結果を使えます。
- **読むだけでなく編集も。** .NET とネイティブコードをメモリ上でパッチし、差分を確認し、検証済みのコピーを保存し、名前と
  パッチを次のビルドへ引き継ぎます。
- **クロスプラットフォーム。** Windows、Linux（glibc と musl）、macOS の x64 と arm64: win-x64、win-arm64、linux-x64、
  linux-arm64、linux-musl-x64、linux-musl-arm64、osx-x64、osx-arm64。

対応クライアント: Claude Code、Claude Desktop、Cursor、Windsurf、VS Code、VS Code Insiders、VSCodium、Cline、Roo Code、
Kilo Code、Visual Studio、Codex、Gemini CLI、Qwen Code、GitHub Copilot CLI、OpenCode、Crush、Zed、LM Studio、
Amazon Q、Kiro、Antigravity、Devin、Command Code、Grok Build、OMP、Pi、Kimi Code、Qoder、Factory Droid、Trae、
CodeBuddy、Hermes、DeepSeek Harness。その他のクライアント: `corvus config`。

## ドキュメント

[インストール](docs/installation.md) · [設定](docs/configuration.md) · [機能](docs/features.md) · [ツールリファレンス](docs/tools.md) ·
[コマンドライン](docs/cli.md) · [エラー](docs/errors.md) · [トラブルシューティング](docs/troubleshooting.md) ·
[FAQ](docs/faq.md) · [リリースノート](docs/release-notes.md) · [全ページ](docs/README.md)

ガイド: [最初のセッション](docs/guides/1-first-session.md) · [デコードとパッチ](docs/guides/2-decode-and-patch.md) ·
[新しいビルド](docs/guides/3-new-build.md)。

## 責任ある利用

所有している、または解析を許可されているソフトウェアだけを解析してください。サードパーティのコードの逆コンパイル、パッチ、
再配布は、そのライセンスやお住まいの地域の法律によって制限される場合があります。

[コントリビューション](CONTRIBUTING.md) · [セキュリティ](SECURITY.md) · [Apache-2.0 ライセンス](LICENSE)

## スター履歴

<a href="https://www.star-history.com/#Albasha0x0/Corvus&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date&theme=dark" />
    <img alt="Corvus star history" src="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date" />
  </picture>
</a>
