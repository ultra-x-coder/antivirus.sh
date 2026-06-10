<div align="center">

# 🛡️ antivirus.sh

**스크립트 하나로 끝내는 리눅스 보안: 악성코드 검사, 네트워크 점검, 시스템 하드닝.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **웹사이트 및 전체 문서: [antivirus.sh](https://antivirus.sh/ko/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh`는 리눅스 서버의 악성코드를 검사하고 네트워크·시스템 보안을 점검하며, 원한다면 발견한 문제를 바로 고쳐 주기까지 하는 단일 Bash 스크립트입니다. **갓 만든 VM을 단 한 번의 실행으로 하드닝된 상태까지** 끌어올리고, 운영 중인 서버는 아무것도 건드리지 않고 점검만 하도록 설계되었습니다.

의존성도, 에이전트도, 데몬도 없습니다. 오직 Bash뿐 — **모든 Ubuntu 버전**에서의 동작을 보장하며, Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE 등에서도 best-effort 모드로 동작합니다.

## ⚡ 빠른 시작

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

**root**로 실행하면 전체 범위를, **일반 사용자**로 실행하면 축소된 범위를 검사하며, 그 차이를 명확하게 보고합니다.

## 🔍 검사 항목 — 70가지 이상

**악성코드 & 루트킷**
- 알려진 악성코드/암호화폐 채굴기 프로세스 이름과 명령행 (xmrig, kinsing, kdevtmpfsi 등)
- `/tmp`, `/dev/shm`에서 실행 중인 프로세스, 바이너리가 삭제된 채 돌고 있는 프로세스, 파일리스 `memfd` 실행 파일
- 숨겨진 프로세스(readdir 은닉 방식 커널 루트킷 테스트), 의심스러운 커널 모듈
- `/etc/ld.so.preload` 및 `LD_PRELOAD` 유저랜드 루트킷 벡터
- 스크립트, cron 작업, systemd 유닛, 셸 프로필, udev 규칙, MOTD 스크립트 안의 리버스 셸·드로퍼·채굴기 패턴
- `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`에 숨겨진 실행 파일
- 패키지 체크섬 대비 핵심 시스템 바이너리 무결성 검증 (`dpkg -V` / `rpm -V`)
- **ClamAV**, **rkhunter**, **chkrootkit**을 이용한 선택적 정밀 검사 (자동 감지, 플래그 하나로 설치)

**네트워크**
- 수신 대기 중인 모든 포트와 해당 프로세스, 노출 범위 분석 (루프백 전용 vs 외부 전체 공개)
- 위험하게 노출된 서비스: Telnet, 인증 없는 Redis/Mongo/Elasticsearch, Docker API :2375, SMB, RDP, VNC, r-services 등
- 알려진 마이닝 풀/IRC 봇넷 포트로 수립된 연결
- 방화벽 상태: UFW, firewalld, nftables, 순수 iptables — IPv6 커버리지 포함
- 프러미스큐어스 모드 인터페이스, ARP 스푸핑 징후, DNS 리졸버, `/etc/hosts` 하이재킹

**시스템**
- SSH 데몬 점검: root 로그인, 패스워드 인증, 빈 패스워드, X11, 타임아웃, 재시도 횟수
- 계정: 추가 UID 0 사용자, 빈 패스워드, 중복 UID, 셸이 부여된 시스템 계정, NOPASSWD sudo, 무차별 대입 공격 흔적
- 미적용 보안 업데이트, unattended-upgrades, EOL 릴리스 감지, 재부팅 필요 여부
- sysctl 기반 커널 하드닝: ASLR, syncookies, 리다이렉트, 소스 라우팅, ptrace 범위, dmesg/kptr 제한 등
- 파일 권한: `/etc/shadow`, sudoers, SSH 호스트 키, crontab, GRUB; 화이트리스트 대비 SUID/SGID 점검; 전역 쓰기 가능 파일·디렉터리; 소유자 없는 파일; immutable 플래그를 이용한 악성코드의 파일 잠금
- 지속성(persistence) 전수 점검: cron, systemd 유닛, `rc.local`, `at`, 셸 시작 파일, (시스템 계정을 포함한) 모든 사용자의 `authorized_keys`, 서드파티 APT 저장소
- AppArmor/SELinux, auditd, NTP 동기화, 영구 로깅, 코어 덤프, `/dev/shm` 및 `/tmp` 마운트 옵션, CPU 취약점 완화, Docker 보안 (소켓 권한, privileged 컨테이너, docker 그룹)

## 🧰 동작 모드

| 명령 | 동작 |
|---|---|
| `sudo bash antivirus.sh` | 대화형: 모든 수정 사항을 하나씩 보여 주고 확인을 받습니다 |
| `--audit` | 보고만 수행 — 어떤 변경도 없음을 보장합니다 |
| `--fix` | 안전한 수정 사항을 모두 자동 적용합니다 |
| `--harden` | 새 VM 전체 하드닝: 방화벽, SSH, fail2ban, sysctl, 자동 업데이트, auditd, 각종 정책 + 관리자 계정 생성 제안 |
| `--create-user` | SSH 키를 갖춘 sudo 사용자를 단계별로 안내하며 생성 |
| `--scan /path` | 특정 디렉터리 악성코드 검사 |
| `--network` / `--system` / `--malware` | 한 영역만 실행 |
| `--rollback` | 마지막 실행에서 변경한 모든 내용을 되돌리기 |
| `--quick` / `--full` | 더 빠른 / 가장 깊은 검사 |
| `--report file.txt` | 보고서 저장 |

## 🛟 안전 설계

원격 접속을 끊을 수 있는 수정 사항은 **절대 말없이 적용되지 않습니다**:

- 방화벽을 켜기 전에 **사용 중인 SSH 포트를 먼저 허용**합니다 (sshd 설정, 활성 소켓, `$SSH_CONNECTION`에서 파싱);
- `PasswordAuthentication no`는 sudo 권한이 있는 사용자에게 실제로 SSH 키가 있지 않은 한 **거부**됩니다;
- 새로운 sshd 설정은 reload **전에** 항상 `sshd -t`로 검증합니다 — 잘못된 설정은 자동으로 원복되며, 기존 세션은 절대 끊기지 않습니다;
- 수정된 모든 파일은 백업되며, `--rollback`으로 전부 복원할 수 있습니다;
- 의심스러운 파일은 삭제하지 않고 **격리**합니다 (이동 + `chmod 000`).

종료 코드: `0` 정상 · `1` 경고 · `2` 심각한 발견 — cron/CI에서 그대로 활용할 수 있습니다.

## 📊 출력 예시

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

## 📚 전체 문서

상세 검사 카탈로그, FAQ, 하드닝 가이드와 예제: **[https://antivirus.sh/ko/](https://antivirus.sh/ko/)**

## ⚠️ 면책 조항

`antivirus.sh`는 방어적 점검·하드닝 도구입니다. 공격 표면을 줄이고 흔한 침해 패턴을 탐지하지만, 모든 위협을 막아 준다는 보장은 아닙니다. 커널 수준 침해가 확인된 시스템이라면, 깨끗한 이미지로 다시 구축하는 것만이 유일하게 안전한 해결책입니다.

## 📄 라이선스

[MIT](LICENSE) — 개인·상업적 사용 모두 무료입니다.

**이 도구가 도움이 되었다면 ⭐ 스타를 눌러 주시고 [antivirus.sh](https://antivirus.sh)를 공유해 주세요.**
