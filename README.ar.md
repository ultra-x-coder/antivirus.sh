# antivirus_whole

<div align="center">

**مضاد فيروسات وماسح برمجيات خبيثة للينكس داخل سكربت Bash واحد.**

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | العربية | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` هو ماسح Bash مستقل لخوادم لينكس. يركز على اكتشاف البرمجيات الخبيثة، وفحص نقاط الاستمرارية، ومراجعة العمليات، والتحقق من سلامة الحزم، وبعض مؤشرات الشبكة، مع عزل آمن للملفات المشبوهة. يحتوي هذا المستودع على جزء مكافحة البرمجيات الخبيثة فقط بعد فصله من الحزمة الأمنية الأكبر `antivirus.sh`.

تمت صياغة هذا README بأسلوب قريب من المشروع المرجعي: <https://github.com/ultra-x-coder/antivirus.sh/>

## بداية سريعة

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## ما الذي يفحصه

- أنماط الـ reverse shell وdroppers وعمال التعدين والأبواب الخلفية
- الملفات التنفيذية المخفية داخل `/tmp` و`/var/tmp` و`/dev/shm`
- أسماء العمليات الخبيثة المعروفة وعمليات `memfd`
- الاستمرارية عبر cron وsystemd و`rc.local` وملفات بدء الصدفة وudev و`authorized_keys`
- الاتصالات الخارجة إلى المنافذ الشائعة لمجمعات التعدين أو شبكات IRC botnet
- سلامة الملفات الثنائية الحرجة عبر `dpkg -V` أو `rpm -V`
- فحوصات إضافية عبر ClamAV وrkhunter وchkrootkit عند توفرها

## الأوضاع

| الأمر | الوصف |
| --- | --- |
| `sudo bash antivirus.sh` | وضع تفاعلي مع تأكيد كل إصلاح. |
| `sudo bash antivirus.sh --audit` | تقرير فقط بدون أي تغيير. |
| `sudo bash antivirus.sh --fix` | تطبيق الإصلاحات الآمنة تلقائيا. |
| `sudo bash antivirus.sh --install-tools` | تثبيت ClamAV وrkhunter وchkrootkit. |

## الخيارات

`--scan PATH` و `--exclude PATH` و `--quick` و `--full` و `--yes` و `--no-external` و `--report FILE` و `--no-color` و `--version` و `--help`

## الأمان

- الملفات المشبوهة تُعزل ولا تُحذف مباشرة.
- وضع `--audit` هو الأنسب للمراجعة على الخوادم الإنتاجية.
- التشغيل بصلاحية `root` يعطي التغطية الكاملة.

## المخرجات

- رموز الخروج: `0` نظيف، `1` تحذيرات، `2` نتائج حرجة
- تقارير root: `/var/log/antivirus-whole/`
- عزل root: `/var/lib/antivirus-whole/quarantine/`
- بدون root: `~/.antivirus-whole/log/` و `~/.antivirus-whole/quarantine/`

## الترخيص

MIT كما هو مذكور في ترويسة السكربت.
