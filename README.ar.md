<div align="center">

# 🛡️ antivirus.sh

**سكربت واحد. أمان لينكس كامل: فحص البرمجيات الخبيثة، تدقيق الشبكة، تحصين النظام.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **الموقع والتوثيق الكامل: [antivirus.sh](https://antivirus.sh/ar/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` هو سكربت Bash واحد مستقل بذاته يفحص خادم لينكس بحثًا عن البرمجيات الخبيثة، ويدقّق أمان الشبكة والنظام، و— إن أردت — يصلح ما يجده. صُمِّم ليأخذ **جهازًا افتراضيًا جديدًا إلى حالة محصَّنة في تشغيلة واحدة**، وليدقّق الأجهزة القائمة من دون تغيير أي شيء.

لا اعتماديات. لا وكلاء (agents). لا خدمات خلفية (daemons). فقط Bash — يعمل بشكل مضمون على **كل إصدارات Ubuntu**، وبوضع أفضل جهد على Debian وRHEL/CentOS/Alma/Rocky وFedora وArch وopenSUSE وغيرها.

## ⚡ البداية السريعة

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

يعمل بصلاحيات **root** (تغطية كاملة) وكمستخدم **عادي** (تغطية مخفَّضة يُبلَّغ عنها بوضوح).

## 🔍 ما الذي يفحصه — أكثر من 70 فحصًا

**البرمجيات الخبيثة وأدوات rootkit**
- أسماء عمليات وأسطر أوامر البرمجيات الخبيثة وبرامج تعدين العملات المعروفة (xmrig وkinsing وkdevtmpfsi، …)
- العمليات التي تعمل من `/tmp` و`/dev/shm`، والثنائيات المحذوفة، وملفات `memfd` التنفيذية عديمة الملفات
- العمليات المخفية (اختبار rootkit النواة المعتمد على إخفاء readdir)، ووحدات النواة المشبوهة
- متجهات rootkit في مساحة المستخدم عبر `/etc/ld.so.preload` و`LD_PRELOAD`
- أنماط reverse shells وأدوات الإسقاط (droppers) وبرامج التعدين داخل السكربتات ومهام cron ووحدات systemd وملفات تهيئة الصدفة وقواعد udev وسكربتات MOTD
- ملفات تنفيذية مخفية في `/tmp` و`/var/tmp` و`/dev/shm` و`/dev`
- التحقق من سلامة ثنائيات النظام الأساسية مقابل مجاميع تحقق الحزم (`dpkg -V` / `rpm -V`)
- فحوص عميقة اختيارية باستخدام **ClamAV** و**rkhunter** و**chkrootkit** (اكتشاف تلقائي، وتثبيت بخيار واحد)

**الشبكة**
- كل منفذ يستمع مع العملية المالكة، وتحليل درجة الانكشاف (loopback مقابل العالم الخارجي)
- الخدمات الخطرة المكشوفة: Telnet، وRedis/Mongo/Elasticsearch من دون مصادقة، وواجهة Docker API على المنفذ ‎:2375، وSMB، وRDP، وVNC، وخدمات r-services …
- الاتصالات القائمة بمنافذ مجمّعات التعدين / شبكات بوتات IRC المعروفة
- حالة جدار الحماية: UFW وfirewalld وnftables وiptables الخام — بما في ذلك تغطية IPv6
- الواجهات في الوضع المختلط (promiscuous)، ومؤشرات ARP-spoofing، ومحلّلات DNS، واختطاف `/etc/hosts`

**النظام**
- تدقيق خادم SSH: دخول root، والمصادقة بكلمة مرور، وكلمات المرور الفارغة، وX11، والمهل الزمنية، وعدد المحاولات
- الحسابات: مستخدمو UID-0 إضافيون، وكلمات مرور فارغة، ومعرّفات UID مكررة، وحسابات نظام تملك صدفة دخول، وقواعد sudo بصيغة NOPASSWD، وأدلة على هجمات brute-force
- تحديثات الأمان المعلّقة، وunattended-upgrades، واكتشاف الإصدارات المنتهية الدعم (EOL)، والحاجة إلى إعادة التشغيل
- تحصين النواة عبر sysctl: ‏ASLR، وsyncookies، وإعادة التوجيه، والتوجيه المصدري، ونطاق ptrace، وقيود dmesg/kptr …
- أذونات الملفات: `/etc/shadow`، وsudoers، ومفاتيح مضيف SSH، وcrontab، وGRUB؛ وتدقيق SUID/SGID مقابل قائمة بيضاء؛ والملفات والمجلدات القابلة للكتابة من الجميع؛ والملفات بلا مالك؛ وأقفال البرمجيات الخبيثة بعلم المنع من التعديل (immutable)
- مسح نقاط الاستمرارية: cron، ووحدات systemd، و`rc.local`، و`at`، وملفات بدء تشغيل الصدفة، و`authorized_keys` لكل مستخدم (بما في ذلك حسابات النظام)، ومستودعات APT الخارجية
- AppArmor/SELinux، وauditd، ومزامنة NTP، والتسجيل الدائم، وملفات core dump، وخيارات تركيب `/dev/shm` و`/tmp`، وتخفيفات ثغرات المعالج، وأمان Docker (أذونات المقبس، والحاويات المميّزة، ومجموعة docker)

## 🧰 الأوضاع

| الأمر | ما يفعله |
|---|---|
| `sudo bash antivirus.sh` | تفاعلي: يُعرض كل إصلاح ويُؤكَّد قبل تطبيقه |
| `--audit` | تقرير فقط — صفر تغييرات مضمونة |
| `--fix` | تطبيق جميع الإصلاحات الآمنة تلقائيًا |
| `--harden` | تحصين كامل لجهاز افتراضي جديد: جدار الحماية، وSSH، وfail2ban، وsysctl، والتحديثات التلقائية، وauditd، والسياسات + عرضٌ لإنشاء مستخدم إداري |
| `--create-user` | إنشاء موجَّه لمستخدم sudo مع مفتاح SSH |
| `--scan /path` | فحص مجلد محدد بحثًا عن البرمجيات الخبيثة |
| `--network` / `--system` / `--malware` | تشغيل مجال واحد فقط |
| `--rollback` | التراجع عن كل تغييرات التشغيلة الأخيرة |
| `--quick` / `--full` | فحص أسرع / أعمق |
| `--report file.txt` | حفظ التقرير |

## 🛟 تصميم يضع السلامة أولًا

الإصلاحات التي قد تقطع الوصول البعيد **لا تُطبَّق أبدًا بصمت**:

- تفعيل جدار الحماية **يسمح مسبقًا بمنفذ (منافذ) SSH الخاصة بك** أولًا (تُستخرج من sshd والمقابس الحية و`$SSH_CONNECTION`)؛
- يُرفض تطبيق `PasswordAuthentication no` ما لم يكن لدى مستخدم يملك صلاحيات sudo مفتاح SSH فعلًا؛
- كل إعداد جديد لـ sshd يُتحقق منه عبر `sshd -t` **قبل** إعادة التحميل — الإعدادات غير الصالحة تُستعاد تلقائيًا، والجلسات القائمة لا تُقطع أبدًا؛
- كل ملف معدَّل يُنسخ احتياطيًا؛ و`--rollback` يستعيد كل شيء؛
- الملفات المشبوهة **تُعزل** (تُنقل + `chmod 000`) ولا تُحذف أبدًا.

رموز الخروج: `0` نظيف · `1` تحذيرات · `2` نتائج حرجة — مناسبة لـ cron وCI.

## 📊 مثال على المخرجات

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

## 📚 التوثيق الكامل

كتالوج الفحوص المفصّل، والأسئلة الشائعة، ودليل التحصين، والأمثلة: **[https://antivirus.sh/ar/](https://antivirus.sh/ar/)**

## ⚠️ إخلاء مسؤولية

`antivirus.sh` أداة دفاعية للتدقيق والتحصين. وهي تقلّص سطح الهجوم وتكتشف أنماط الاختراق الشائعة؛ لكنها ليست ضمانة ضد كل تهديد. وبالنسبة لجهاز ثبت اختراقه على مستوى النواة، فالحل الآمن الوحيد هو إعادة البناء من صورة نظيفة.

## 📄 الرخصة

[MIT](LICENSE) — مجانية للاستخدام الشخصي والتجاري.

**إن أفادتك هذه الأداة، فامنح المستودع نجمة ⭐ وشارك [antivirus.sh](https://antivirus.sh).**
