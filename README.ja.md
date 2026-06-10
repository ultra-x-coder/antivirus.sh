<div align="center">

# 🛡️ antivirus.sh

**1本のスクリプトで、Linuxセキュリティのすべてを。マルウェアスキャン、ネットワーク監査、システムハードニング。**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **ウェブサイトと完全なドキュメント: [antivirus.sh](https://antivirus.sh/ja/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` は、Linuxサーバーのマルウェアスキャン、ネットワークとシステムのセキュリティ監査、そして必要に応じて検出した問題の修復までを行う、単一の自己完結型Bashスクリプトです。**まっさらなVMを1回の実行でハードニング済みの状態に**仕上げることも、既存のマシンを一切変更せずに監査することもできるように作られています。

依存関係なし。エージェントなし。デーモンなし。あるのはBashだけ。**すべてのUbuntuバージョン**での動作を保証し、Debian、RHEL/CentOS/Alma/Rocky、Fedora、Arch、openSUSEなどでもベストエフォートで動作します。

## ⚡ クイックスタート

```bash
# download
curl -fsSL https://raw.githubusercontent.com/TARGET_PLEVEHOLDER/antivirus.sh/main/antivirus.sh -o antivirus.sh

# read-only audit (changes nothing, safe everywhere)
sudo bash antivirus.sh --audit

# interactive mode: shows each problem and asks before fixing
sudo bash antivirus.sh

# harden a brand-new VM end-to-end
sudo bash antivirus.sh --harden
```

**root**（フルカバレッジ）でも**一般ユーザー**（カバレッジは限定され、その旨が明確に報告されます）でも動作します。

## 🔍 チェック内容 — 70以上のチェック項目

**マルウェアとルートキット**
- 既知のマルウェア／クリプトマイナーのプロセス名とコマンドライン（xmrig、kinsing、kdevtmpfsi など）
- `/tmp` や `/dev/shm` から実行されているプロセス、バイナリが削除済みのプロセス、ファイルレスな `memfd` 実行ファイル
- 隠しプロセス（readdir 隠蔽型カーネルルートキットのテスト）、不審なカーネルモジュール
- `/etc/ld.so.preload` と `LD_PRELOAD` によるユーザーランド・ルートキットの侵入経路
- スクリプト、cron ジョブ、systemd ユニット、シェルプロファイル、udev ルール、MOTD スクリプト内のリバースシェル、ドロッパー、マイナーのパターン
- `/tmp`、`/var/tmp`、`/dev/shm`、`/dev` 内の隠し実行ファイル
- パッケージのチェックサムによるコアシステムバイナリの整合性検証（`dpkg -V` / `rpm -V`）
- **ClamAV**、**rkhunter**、**chkrootkit** によるオプションのディープスキャン（自動検出、フラグ1つでインストール）

**ネットワーク**
- リッスン中の全ポートをプロセス付きで一覧し、公開状況を分析（ループバックのみか、外部公開か）
- 危険な公開サービス: Telnet、認証なしの Redis/Mongo/Elasticsearch、Docker API :2375、SMB、RDP、VNC、r-services など
- 既知のマイニングプール／IRC ボットネットのポートへの確立済み接続
- ファイアウォールの状態: UFW、firewalld、nftables、素の iptables — IPv6 のカバレッジも含む
- プロミスキャスモードのインターフェース、ARP スプーフィングの兆候、DNS リゾルバ、`/etc/hosts` の改ざん

**システム**
- SSH デーモンの監査: root ログイン、パスワード認証、空パスワード、X11、タイムアウト、リトライ回数
- アカウント: 余分な UID 0 ユーザー、空パスワード、UID の重複、シェルを持つシステムアカウント、NOPASSWD な sudo、ブルートフォース攻撃の痕跡
- 未適用のセキュリティアップデート、unattended-upgrades、EOL リリースの検出、再起動の要否
- sysctl によるカーネルハードニング: ASLR、syncookies、リダイレクト、ソースルーティング、ptrace スコープ、dmesg/kptr の制限など
- ファイルパーミッション: `/etc/shadow`、sudoers、SSH ホスト鍵、crontab、GRUB。ホワイトリストに基づく SUID/SGID 監査。誰でも書き込み可能なファイルとディレクトリ。所有者不明のファイル。immutable フラグによるマルウェアのロック
- 永続化の総点検: cron、systemd ユニット、`rc.local`、`at`、シェル起動ファイル、全ユーザー（システムアカウントを含む）の `authorized_keys`、サードパーティの APT リポジトリ
- AppArmor/SELinux、auditd、NTP 同期、永続ロギング、コアダンプ、`/dev/shm` と `/tmp` のマウントオプション、CPU 脆弱性の緩和策、Docker のセキュリティ（ソケットのパーミッション、特権コンテナ、docker グループ）

## 🧰 モード

| コマンド | 動作 |
|---|---|
| `sudo bash antivirus.sh` | 対話モード: すべての修正を表示し、確認のうえ適用 |
| `--audit` | レポートのみ — 変更ゼロを保証 |
| `--fix` | 安全な修正をすべて自動適用 |
| `--harden` | 新規VMのフルハードニング: ファイアウォール、SSH、fail2ban、sysctl、自動アップデート、auditd、各種ポリシー。さらに管理者ユーザーの作成も提案 |
| `--create-user` | SSH 鍵付き sudo ユーザーのガイド付き作成 |
| `--scan /path` | 指定ディレクトリのマルウェアスキャン |
| `--network` / `--system` / `--malware` | 特定の領域のみを実行 |
| `--rollback` | 前回の実行によるすべての変更を取り消し |
| `--quick` / `--full` | より高速なスキャン／最も深いスキャン |
| `--report file.txt` | レポートをファイルに保存 |

## 🛟 安全設計

リモートアクセスを遮断しかねない修正は、**決して黙って適用されません**:

- ファイアウォールを有効化する前に、**SSH ポートを事前に許可**します（sshd の設定、稼働中のソケット、`$SSH_CONNECTION` から検出）。
- sudo 権限を持つユーザーが実際に SSH 鍵を持っていない限り、`PasswordAuthentication no` は**拒否されます**。
- 新しい sshd 設定はリロード**前に** `sshd -t` で検証されます。無効な設定は自動的に元へ戻され、既存のセッションが切断されることはありません。
- 変更されたファイルはすべてバックアップされ、`--rollback` ですべて復元できます。
- 不審なファイルは削除せず、**隔離**します（移動して `chmod 000`）。

終了コード: `0` 問題なし · `1` 警告あり · `2` 重大な検出あり — cron や CI にそのまま組み込めます。

## 📊 出力例

```
==> Firewall
  [CRIT] NO active firewall detected — every listening service is fully exposed
  ?  RISKY fix: enable a firewall (UFW) with SSH port(s) pre-allowed [y/N] y
  [FIX ] enable a firewall (UFW/firewalld) with SSH port(s) pre-allowed

==> Processes & memory
  [ OK ] no known malware/miner process signatures
  [ OK ] no hidden processes (readdir-hiding rootkit test passed)

  security score: 86/100  grade: B — good
```

## 📚 完全なドキュメント

チェック項目の詳細カタログ、FAQ、ハードニングガイド、各種サンプルはこちら: **[https://antivirus.sh/ja/](https://antivirus.sh/ja/)**

## ⚠️ 免責事項

`antivirus.sh` は防御目的の監査・ハードニングツールです。攻撃対象領域を減らし、典型的な侵害パターンを検出しますが、あらゆる脅威を防ぐ保証ではありません。カーネルレベルの侵害が確認されたマシンに対する唯一の安全な対処は、クリーンなイメージからの再構築です。

## 📄 ライセンス

[MIT](LICENSE) — 個人利用・商用利用ともに無料です。

**このツールが役に立ったら、ぜひリポジトリに ⭐ スターを付けて、[antivirus.sh](https://antivirus.sh) をシェアしてください。**
