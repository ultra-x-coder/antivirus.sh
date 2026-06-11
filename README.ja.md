# antivirus.sh

<div align="center">

**1 本の Bash スクリプトで動く Linux 向けアンチウイルス兼マルウェアスキャナ。**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](antivirus.sh)
[![Shell](https://img.shields.io/badge/Shell-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-supported-E95420.svg)](antivirus.sh)
[![Debian](https://img.shields.io/badge/Debian-best--effort-A81D33.svg)](antivirus.sh)
[![RHEL/CentOS](https://img.shields.io/badge/RHEL%2FCentOS-best--effort-EE0000.svg)](antivirus.sh)
[![Fedora](https://img.shields.io/badge/Fedora-best--effort-51A2DA.svg)](antivirus.sh)
[![Arch](https://img.shields.io/badge/Arch-best--effort-1793D1.svg)](antivirus.sh)
[![openSUSE](https://img.shields.io/badge/openSUSE-best--effort-73BA25.svg)](antivirus.sh)
[![No agent](https://img.shields.io/badge/No%20agent-no%20daemon-lightgrey.svg)](antivirus.sh)

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | 日本語 | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` は Linux サーバ向けの自己完結型 Bash スキャナです。マルウェア検出、永続化ポイントの監査、プロセス検査、パッケージ整合性確認、基本的なネットワーク指標の確認、隔離を行います。このリポジトリには、より大きな `antivirus.sh` セキュリティスイートから切り出したアンチウイルス部分のみが含まれます。

README の構成は参考プロジェクトの見せ方を踏まえています: <https://github.com/ultra-x-coder/antivirus.sh/>

## クイックスタート

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## 主なチェック内容

- リバースシェル、ドロッパー、マイナー、一般的なバックドアパターン
- `/tmp`、`/var/tmp`、`/dev/shm` 内の隠し実行ファイル
- 既知の不正プロセス名、`memfd` プロセス、一時ディレクトリ起動バイナリ
- cron、systemd、`rc.local`、シェル初期化、udev、`authorized_keys` の永続化
- マイニングプールや IRC ボットネットで使われやすいポートへの外向き接続
- `dpkg -V` または `rpm -V` による重要バイナリの整合性確認
- インストール済みなら ClamAV、rkhunter、chkrootkit の追加スキャン

## モード

| コマンド | 説明 |
| --- | --- |
| `sudo bash antivirus.sh` | 対話モード。各修正を確認します。 |
| `sudo bash antivirus.sh --audit` | 読み取り専用監査。変更なし。 |
| `sudo bash antivirus.sh --fix` | 安全と判断した修正を自動適用します。 |
| `sudo bash antivirus.sh --install-tools` | ClamAV、rkhunter、chkrootkit を導入します。 |

## オプション

`--scan PATH`、`--exclude PATH`、`--quick`、`--full`、`--yes`、`--no-external`、`--report FILE`、`--no-color`、`--version`、`--help`

## 安全性

- 疑わしいファイルは削除ではなく隔離されます。
- 本番環境ではまず `--audit` を使うのが妥当です。
- 完全な検査には `root` 実行が推奨です。

## 出力

- 終了コード: `0` 正常, `1` 警告, `2` 重大な検出
- `root` レポート: `/var/log/antivirus-whole/`
- `root` 隔離: `/var/lib/antivirus-whole/quarantine/`
- 非 root: `~/.antivirus-whole/log/` と `~/.antivirus-whole/quarantine/`

## ライセンス

スクリプトヘッダに記載のとおり MIT です。
