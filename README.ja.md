# Corvus

[English](README.md) · [简体中文](README.zh-CN.md) · **日本語**

コンパイル済みプログラムのリバースエンジニアリングとセキュリティ分析のための MCP サーバー：.NET アセンブリと、ネイティブの
PE、ELF、Mach-O バイナリ。

[![Release](https://img.shields.io/github/v/release/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Albasha0x0/Corvus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Albasha0x0/Corvus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Albasha0x0/Corvus?style=flat-square)](https://github.com/Albasha0x0/Corvus/stargazers)

- 自己完結型の単一バイナリ。何もアップロードせず、既定では読み取ったものを実行しません。
- ツールと出力はリリース間で変わることがあります。[リリースノート](docs/release-notes.md)を参照してください。本書は [README.md](README.md) の翻訳で、英語版が優先します。

## クイックスタート

Windows（PowerShell）：

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

Linux と macOS：

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

インストーラーはダウンロードを検証し、見つかった MCP クライアントに Corvus を登録します。クライアントを再起動して次のように尋ねます：

> Corvus で app.dll を読み込み、エクスポートファイルをどう作るか説明して。読んだメソッドを示して。

- プラグイン、コンテナーイメージ、その他のクライアント：[インストール](docs/installation.md)。
- ターミナルから：`corvus decompile_member --load app.dll member=Ns.Type::Method`（[コマンドライン](docs/cli.md)）。
- ビルド：win-x64、win-arm64、linux-x64、linux-arm64、linux-musl-x64、linux-musl-arm64、osx-x64、osx-arm64。

## 仕組み

- エージェントは MCP で Corvus を呼び出します。結果には上限があり、リストはページングされ、エラーは次の手順を示します。
- Corvus 独自のエンジンがネイティブコード（x86、x64、ARM32、ARM64）を読みます。IDA または Ghidra があれば疑似コードが加わります。
- 編集はメモリ内で行い、エージェントが差分を確認してパッチ済みのコピーを保存します。

## 読み取れるもの

| 入力 | 表示 | 必要なもの |
|---|---|---|
| .NET アセンブリ | C#、IL、参照、コールグラフ、パッチ | なし |
| ネイティブ PE、ELF、Mach-O | 関数、逆アセンブル、相互参照、型、パッチ | なし |
| ネイティブ疑似コード | 逆コンパイルした関数、エンジンの型、スクリプト | IDA 9 または Ghidra 12 |
| NativeAOT、ReadyToRun、Il2Cpp | メソッド名とアドレス、文字列 | なし |
| WebAssembly | モジュール、コンポーネント、逆アセンブル | なし |
| コンテナー | 単一ファイルバンドル、APK、IPA、インストーラー、ディスクイメージ、ファームウェア | なし |
| ドキュメントとスクリプト | Office マクロ、PDF アクション、難読化を解除したスクリプト | なし |
| インストール前のパッケージ | npm、PyPI、拡張機能パッケージ | なし |
| ネットワークキャプチャ | pcap ストリーム、HTTP オブジェクト、キーログで復号した TLS | なし |
| Android | マニフェスト、リソース、DEX、Java | Java には JADX、デバイスには adb |
| クラッシュダンプ | ミニダンプ、コアダンプ、スタック、.NET ヒープ | なし |
| 実行中のプログラム | 停止ポイント、呼び出しの記録、コードカバレッジ | Frida 17.24.3 以降の 17.x、既定ではオフ |

全 165 ツールと 15 プロンプト：[機能](docs/features.md)、[ツールリファレンス](docs/tools.md)。

## ショーケース

- [逆コンパイル、再ビルド、実行](docs/showcase/round-trip.md)：ビルドして実行できる C# プロジェクトとしてエクスポートしたアセンブリ。
- [単一ファイルアプリの中身](docs/showcase/single-file.md)：実行せずに展開した .NET 単一ファイル実行可能ファイル。
- [SQLite はどこで乱数を作るか](docs/showcase/sqlite-random.md)：呼び出し元までたどった暗号定数。
- [Json.NET のエラーをコードまでたどる](docs/showcase/json-reference-loop.md)：設定までたどったエラーメッセージ。

ガイド：[最初のセッション](docs/guides/1-first-session.md) · [デコードとパッチ](docs/guides/2-decode-and-patch.md) ·
[新しいビルド](docs/guides/3-new-build.md)。すべての手順をテストが実行します。

## ドキュメント

[インストール](docs/installation.md) · [設定](docs/configuration.md) · [機能](docs/features.md) ·
[ツールリファレンス](docs/tools.md) · [コマンドライン](docs/cli.md) · [エラー](docs/errors.md) ·
[トラブルシューティング](docs/troubleshooting.md) · [FAQ](docs/faq.md) · [リリースノート](docs/release-notes.md) ·
[全ページ](docs/README.md)

## 責任ある利用

自分が所有するか分析を許可されたソフトウェアだけを分析してください。ライセンスや現地の法律により、逆コンパイル、パッチ、再配布が制限されることがあります。

[コントリビューション](CONTRIBUTING.md) · [セキュリティ](SECURITY.md) · [Apache-2.0 ライセンス](LICENSE)

## Star の推移

<a href="https://www.star-history.com/#Albasha0x0/Corvus&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date&theme=dark" />
    <img alt="Corvus star history" src="https://api.star-history.com/svg?repos=Albasha0x0/Corvus&type=Date" />
  </picture>
</a>
