# SA SSTP for iOS — تجهيز أولي

**الحالة:** تم تعديل وتجهيز ملفات المصدر، لكن لم يتم إنتاج IPA أو إجراء اتصال فعلي على iPhone بعد؛ بيئة العمل الحالية لا تحتوي على macOS/Xcode.

هذا مشروع Flutter مبني على المشروعين المرفوعين:
- `sstp_flutter` الأصلي.
- `vpn_adapter_ios 1.0.0` المرفق محلياً داخل `vendor/`.

## ما تم تجهيزه

- واجهة عربية باسم **SA SSTP**.
- قائمة 37 سيرفر سعودي (SA10–SA46) و12 سيرفر إماراتي (AE02–AE13).
- استبعاد AE01 لأنه فشل فحص TCP في نتائج الفحص المرسلة.
- المنفذ الافتراضي 1194.
- الاتصال بعنوان IP مباشرة، وتمرير اسم النطاق منفصلاً كـ TLS SNI/domain.
- مصادقة PAP افتراضياً، مع خيارات CHAP وMS-CHAPv2.
- إبقاء التحقق من شهادة TLS مفعلاً (`allowInsecure=0`).
- إضافة App Group واحد إلى التطبيق وامتداد Packet Tunnel.
- إنشاء ملف VPN عبر `NETunnelProviderManager` مباشرة وتحديد Bundle ID الخاص بامتداد Packet Tunnel صراحةً.
- إضافة تهيئة الامتداد `setupExtenstionApplication`.
- جعل الاعتماد `vpn_adapter_ios` محلياً، حتى لا يحتاج CocoaPods إلى تنزيله من GitHub.

## حالة التحقق

قائمة السيرفرات مبنية على نتائج الفحص التي أرسلها المستخدم:
- السعودية: 37 نجحت في TCP/TLS.
- الإمارات: 12 نجحت في TCP/TLS.
- نجاح TCP/TLS لا يثبت نجاح مصادقة PPP.
- اتصال PAP سبق اختباره بنجاح مع SA11 وSA29 وSA32 وSA46.
- مصادقة الإمارات وبقية السيرفرات لم تُثبت بعد.

اسم النطاق يُرسل إلى خاصية `SSProtocol.domain` في المكتبة الأصلية بينما يُستخدم IP في `SSProtocol.host`. هذا هو مسار فصل عنوان الاتصال عن اسم TLS، ويجب تأكيده باختبار فعلي على الجهاز.

## متطلبات البناء

لا يمكن إنشاء IPA نهائي من Windows أو بيئة Linux الحالية؛ بناء iOS يحتاج macOS وXcode. لذلك أُضيف GitHub Actions workflow لبناء الحزمة على macOS، ثم تضمين صلاحيات التطبيق والامتداد باستخدام `ldid` قبل تجهيز IPA.

المتطلبات:
- Flutter stable.
- Xcode مع iOS SDK.
- CocoaPods.
- Homebrew لتثبيت `ldid`.
- اتصال إنترنت أثناء تنزيل حزم Flutter/CocoaPods العامة.

## البناء على Mac

من مجلد المشروع:

```bash
chmod +x BUILD_TROLLSTORE_IPA.sh
./BUILD_TROLLSTORE_IPA.sh
```

الناتج:

```text
dist/SA_SSTP_TrollStore.ipa
```

## البناء عبر GitHub Actions من Windows

1. فك ضغط المشروع وارفع محتوياته إلى مستودع GitHub جديد.
2. افتح تبويب **Actions**.
3. اختر **Build SA SSTP TrollStore IPA**.
4. اضغط **Run workflow**.
5. بعد انتهاء البناء، نزّل artifact باسم `SA_SSTP_TrollStore_ipa`.
6. انقل ملف IPA إلى iPhone وثبّته من TrollStore Lite.

يُبنى التطبيق دون توقيع Apple، ثم تُضمَّن entitlements الخاصة بالتطبيق والامتداد داخل توقيعيهما باستخدام `ldid`؛ هذه الخطوة مهمة حتى يحتفظ TrollStore Lite بصلاحيات Packet Tunnel وApp Group عند التثبيت. بعد ذلك يثبت TrollStore Lite الحزمة على الجهاز.

## أول اختبار مقترح

ابدأ بـ **SA46** لأنه سبق أن اتصل على Windows باستخدام حسابك، ثم جرّب SA29 وSA32. بعد ذلك جرّب AE02 باستخدام PAP.

لا تعتبر ظهور حالة Connected وحده دليلاً كافياً؛ تحقق من عنوان IP العام بعد الاتصال. وإذا فشلت المصادقة، جرّب PAP أولاً ثم CHAP أو MS-CHAPv2 حسب نوع الحساب.

## معرفات المشروع

- App bundle: `com.example.sstpFlutterExample`
- Packet Tunnel extension: `com.example.sstpFlutterExample.sstp-extension0`
- App Group: `group.com.example.sstpFlutterExample`

## ملاحظة مهمة عن TrollStore / Dopamine

تضمين entitlement الخاص بـ Packet Tunnel وApp Group في ملفات المشروع لا يضمن وحده أن iOS سيقبل تسجيل الامتداد على الجهاز. يجب اختبار تثبيت IPA وتشغيل شاشة إذن VPN فعلياً على iOS 18.5. إذا رفض النظام الامتداد أو لم يظهر ملف VPN، أرسل نص الخطأ أو صورة منه قبل تغيير أي صلاحيات.

## ملفات التعديل الأساسية

- `example/lib/main.dart` — الواجهة وإدارة الاتصال.
- `example/lib/server_catalog.dart` — قائمة SA/AE وعناوين IP.
- `lib/server.dart` — إضافة حقل SNI منفصل.
- `ios/Classes/SstpFlutterPlugin.m` — إنشاء ملف VPN الأصلي عبر NetworkExtension، وبناء SSTP URI وتمرير SNI ومصادقة PPP.
- `example/ios/sstp_extension/PacketTunnelProvider.m` — تمرير IP وSNI إلى محرك SSTP.
- `example/ios/Runner/Runner.entitlements` و`example/ios/sstp_extension/sstp_extension.entitlements` — App Group وPacket Tunnel.
- `vendor/vpn_adapter_ios/` — المكتبة المرفقة محلياً.
