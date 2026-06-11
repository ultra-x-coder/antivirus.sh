# antivirus_whole

<div align="center">

**단일 Bash 스크립트로 제공되는 Linux 안티바이러스 및 악성코드 스캐너.**

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | 한국어 | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` 는 Linux 서버용 자체 포함형 Bash 스캐너입니다. 악성 파일 탐지, 지속성 지점 점검, 프로세스 검사, 패키지 무결성 확인, 기본 네트워크 지표 점검, 안전한 격리를 수행합니다. 이 저장소에는 더 큰 `antivirus.sh` 보안 스위트에서 분리한 안티바이러스 부분만 포함됩니다.

README 구성은 참고 프로젝트의 문서 스타일을 따랐습니다: <https://github.com/ultra-x-coder/antivirus.sh/>

## 빠른 시작

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## 검사 항목

- 리버스 셸, 드로퍼, 마이너, 일반적인 백도어 패턴
- `/tmp`, `/var/tmp`, `/dev/shm` 내 숨겨진 실행 파일
- 알려진 악성 프로세스 이름, `memfd` 프로세스, 임시 디렉터리 실행 바이너리
- cron, systemd, `rc.local`, 셸 시작 파일, udev, `authorized_keys` 지속성
- 마이닝 풀 또는 IRC 봇넷에서 자주 쓰는 포트로의 외부 연결
- `dpkg -V` 또는 `rpm -V` 를 통한 핵심 바이너리 무결성 점검
- 설치된 경우 ClamAV, rkhunter, chkrootkit 추가 검사

## 모드

| 명령 | 설명 |
| --- | --- |
| `sudo bash antivirus.sh` | 대화형 모드. 각 수정 전에 확인합니다. |
| `sudo bash antivirus.sh --audit` | 읽기 전용 감사. 변경 없음. |
| `sudo bash antivirus.sh --fix` | 안전한 수정 사항을 자동 적용합니다. |
| `sudo bash antivirus.sh --install-tools` | ClamAV, rkhunter, chkrootkit 설치. |

## 옵션

`--scan PATH`, `--exclude PATH`, `--quick`, `--full`, `--yes`, `--no-external`, `--report FILE`, `--no-color`, `--version`, `--help`

## 안전성

- 의심 파일은 삭제하지 않고 격리합니다.
- 운영 서버에서는 먼저 `--audit` 사용이 적절합니다.
- 전체 커버리지를 위해 `root` 실행을 권장합니다.

## 출력

- 종료 코드: `0` 정상, `1` 경고, `2` 치명적 발견
- `root` 보고서: `/var/log/antivirus-whole/`
- `root` 격리: `/var/lib/antivirus-whole/quarantine/`
- 비 root: `~/.antivirus-whole/log/`, `~/.antivirus-whole/quarantine/`

## 라이선스

스크립트 헤더 기준 MIT 입니다.
