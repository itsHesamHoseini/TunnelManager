package main

var cliLanguage = "en"

func cliLabel(label string) string {
	if cliLanguage != "fa" {
		return label
	}
	translations := map[string]string{
		"Mode (controller/node)":        "نوع نصب (controller/node)",
		"Step 2 of 7 — Prerequisites":   "مرحلهٔ ۲ از ۷ — پیش‌نیازها",
		"Step 3 of 7 — Panel domain/IP": "مرحلهٔ ۳ از ۷ — دامنه یا IP پنل",
		"Panel port":                    "پورت پنل",
		"Installation directory":        "پوشهٔ نصب",
		"Step 4 of 7 — TLS (existing/self-signed/acme-http/acme-dns/proxy)": "مرحلهٔ ۴ از ۷ — گواهی (existing/self-signed/acme-http/acme-dns/proxy)",
		"Certificate PEM file":                                          "مسیر فایل گواهی PEM",
		"Private key PEM file":                                          "مسیر فایل کلید خصوصی PEM",
		"Step 5 of 7 — Administrator username":                          "مرحلهٔ ۵ از ۷ — نام کاربری مدیر",
		"Admin password":                                                "رمز عبور مدیر",
		"Password (blank generates a strong one)":                       "رمز عبور (خالی یعنی ساخت رمز قوی)",
		"Rate-limit profile":                                            "پروفایل محدودیت درخواست (standard/strict)",
		"Install/repair this plan? (yes/no)":                            "این برنامه نصب یا ترمیم شود؟ (yes/no)",
		"Controller HTTPS origin":                                       "نشانی HTTPS پنل",
		"One-time enrollment token":                                     "توکن یک‌بارمصرف ثبت سرور",
		"Install native agent, outbound only; no SSH changes? (yes/no)": "عامل با اتصال خروجی نصب شود؟ تنظیمات SSH تغییر نمی‌کند (yes/no)",
		"Independent backup passphrase (16+ characters)":                "رمز مستقل بکاپ (حداقل ۱۶ نویسه)",
		"Backup passphrase":                                             "رمز بکاپ",
		"Apply update? (yes/no)":                                        "به‌روزرسانی اعمال شود؟ (yes/no)",
		"Uninstall? (yes/no)":                                           "نصب حذف شود؟ (yes/no)",
	}
	if translated, ok := translations[label]; ok {
		return translated
	}
	return label
}
