# رفع MiniRack إلى GitHub من ويندوز

**ابدأ بمستودع Private، ولا ترفع مجلد المشروع الشخصي الذي يحتوي مفاتيح حقيقية.**

## إنشاء المستودع
1. سجّل دخولك إلى GitHub وافتح `https://github.com/new`.
2. اسم المستودع: `MiniRack`، و**Visibility = Private** مؤقتًا.
3. لا تحدد إضافة README أو .gitignore لأنهما داخل الحزمة.

## الرفع عبر Git (بعد تثبيت Git for Windows)
افتح PowerShell داخل المجلد المفكوك الذي فيه `README.md` و`platformio.ini` ثم:

```powershell
git init
git add .
git status --short
git commit -m "MiniRack SAIF exhibition source and documentation"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/MiniRack.git
git push -u origin main
```

بدّل `YOUR_USERNAME` بمعرّف GitHub الصحيح. GitHub سيطلب تسجيل الدخول عند الحاجة. إذا ظهر أن `git` غير موجود، ثبّت Git for Windows أو استخدم واجهة GitHub لرفع محتويات هذه الحزمة فقط.

**مهم:** لا ترفع الملف المضغوط كاملًا كملف وحيد إذا أردت عرض الكود والتوثيق بشكل قابل للتصفح؛ فك الضغط وارفع الملفات والمجلدات داخله.

بعد أن تراجع النشر والملكية الفكرية يمكنك تغيير Visibility إلى Public إن رغبت.
