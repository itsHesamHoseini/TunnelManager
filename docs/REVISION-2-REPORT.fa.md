# نتیجهٔ اصلاح TunnelManager — نسخهٔ دوم

هدف محصول این است که مالکِ فروشندهٔ VPN، با کار ترمینالی کمتر، تنظیمات Backhaul را ساده تغییر دهد، تونل یا سرور مشکل‌دار و اقدام بعدی را سریع پیدا کند، و وضعیت واقعی سرورها را در یک نگاه بفهمد. پنل ابزار مدیریت زیرساخت تونل است؛ کاربران و حساب‌های VPN را مدیریت نمی‌کند و سلامت VLESS را از موفقیت TCP نتیجه نمی‌گیرد. React/TypeScript، Go، PostgreSQL، رابط فارسی RTL/Vazirmatn و معماری عاملِ موجود حفظ شده‌اند.

گزارش ۲۰۲۶-۱۰-۲۴؛ نسخهٔ ۰٫۸٫۰ از کد دقیق `d1230c8` هر چهار گیت را گذراند و با درخواست تازهٔ مالک منتشر شد. [آزمون Linux](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249185)، [امنیت/نصب/nginx](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249241)، [انتشار رسمی](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40073441248) موفق‌اند. کنترلر و عامل محلی از نصب‌کنندهٔ خود محصول ارتقا یافتند؛ Chrome عمومی با TLS معتبر، نسخه و کد دقیق، فارسی/انگلیسی، موبایل و پاسخ۴۰۱ موفق است. فایل‌ها، سرویس‌ها، پورت‌ها، کلید اصلی و هویت عاملِ میزبان مرکزی بدون اختلاف حفظ شدند. کنترلر و هر ۱۰ عامل قابل‌دسترسی ارتقا یافته‌اند؛ [گزارش استقرار و محدودیت‌های باقی‌مانده](DEPLOYMENT-0.8.0.md) مرجع شمارش و شواهد است. هیچ تونل موجود پذیرفته یا تغییر داده نشد و آزمون اختلال پروداکشن انجام نشد.

## وضعیت بسته‌ها

| بسته | وضعیت | نتیجه و شاهد | محدودیت باقی‌مانده |
|---|---|---|---|
| WP0 | ناقص فقط در تشخیص قطعی شبکهٔ میزبان‌های مشکل‌دار | تعریف مشترک دسترس‌پذیری، منابع قدیمی خاکستری، مرزهای ۷۰/۹۰، تاریخ شمسی ایزوله، پیام فارسی و شناسهٔ درخواست؛ `TestObservationTruth`، `TestTunnelHealthUsesAuthoritativeNodeAvailability`، `TestRequestIDErrorContract` و Chrome واقعی | بررسی زنده پس از اجازهٔ تازه انجام شد؛ دو میزبان SSH در دسترس نیستند و یک عامل با وجود اجرای پردازه و HTTPS، داده نمی‌فرستد. علت قطعی اختلال شبکه بدون شاهد ادعا نمی‌شود؛ دادهٔ آن‌ها سالم نمایش داده نمی‌شود. |
| WP1 | انجام‌شده؛ شاهد Linux d1230c8 | مهاجرت یک‌طرفه با بکاپ رمزگذاری‌شده، بازگردانی سطرهای واقعی PostgreSQL، حفظ وابستگی‌های Backhaul و تداخل listener ناشناخته؛ تست‌های `TestRetirement*` و `TestUnknownActualListenerStillBlocksPort` و اجرای کامل TCP/WSS | هیچ فایل یا سرویس قدیمی روی میزبان تغییر نمی‌کند. اجرای کامل منبع d1230c8 شامل اصلاح علت خطای API و منوی جدید نیز موفق است. |
| WP2 | ناقص فقط در ویرایش گروهی | شش مفهوم تأییدشده، نگاشت چندردیفی و مقصد پیش‌فرض همین سرور مقصد، معمول/پیشرفته/خام، پیش‌نمایش انسانی، هماهنگی دو طرف و نتیجهٔ مستقل هر طرف؛ هر چهار ویرایش واقعی، HTTP، clone، بازگشت دستی، رد پیش‌بررسی و شکست طرف دوم با تایمر ۹۰ثانیه در اجرای d1230c8 موفق | چرخش گروهی توکن/ویرایش گروهی کانفیگ ساخته نشده؛ بازگشت اتمیک گروهی تأیید نشده است. این استثنا طبق بند WP2 پرامپت صریح گزارش می‌شود؛ دکمهٔ ساختگی ندارد. عملیات گروهی شروع/توقف موجود حفظ شده است. |
| WP3 | پیاده‌سازی انجام‌شده؛ پوشش واقعی نامعلوم | طبقه‌بندی با علت/اقدام، پیش‌نمایش بدون تغییر، بررسی دوبارهٔ شواهد، پذیرش صریح، ویرایش سرویس مشترک و بازگردانی مبنای پذیرفته‌شده در Linux d1230c8 موفق؛ راهنمای خواندنی جایگزینی، نقشهٔ پورت و فایل برنامهٔ تعمیر در Chrome با صفر درخواست نوشتن آزموده شده است | نمونهٔ واقعی کانفیگ از مالک دریافت نشده؛ نسبت پوشش کانفیگ‌های واقعی اندازه‌گیری نشده است. نقشهٔ جایگزینی فقط دادهٔ شناسایی‌شده را نشان می‌دهد و طرف یا پورت نامعلوم نمی‌سازد؛ سرویس خارج از مدیریت را متوقف نمی‌کند. |
| WP4 | انجام‌شده | شش بخش اصلی، تمام ابزارهای پیشرفته، ۹ نشانی قدیمی، Back مرورگر و حفظ فرم پس از رد خروج در Chrome واقعی؛ `navigation-080.txt` و اجرای native d1230c8 | تغییر معماری یا حذف قابلیت Backhaul انجام نشده است. |
| WP5 | انجام‌شده در رابط محلی | خانه با «الان چه نیاز به اقدام دارد؟»، اقدام مستقیم، سه شمارنده، جدول تمام‌عرض و توپولوژی جمع‌شده؛ `TestRevisionHonestyBrowser` در عرض‌های ۱۲۸۰، ۱۴۴۸، ۱۹۲۰ و ۳۹۰ | تصویرهای میزکار محلی «نمونه» هستند؛ تصاویر native از آزمایش Linux جدا هستند. ورود عمومی پروداکشن جدا و بدون ورود به حساب مالک بررسی شده است. |
| WP6 | انجام‌شده در رابط و API محلی | ترتیب نیازمند توجه، نمودار ۲۴ساعت/۷روز با شکاف واقعی، چهار لایه با مبدأ/زمان، متن صریح محدودهٔ شمارندهٔ شبکه؛ `TestDayHistoryIsBoundedMeasuredBucketsWithMissingValues` و Chrome واقعی | دادهٔ قدیمی فاقد نرخ شبکه، نرخ اختراعی نمی‌گیرد. سلامت TCP یا پردازه، سلامت VPN نیست. |
| WP7 | انجام‌شده در محدودهٔ مجاز | ورودی واقعی TCP از سمت مقصد در Linux d1230c8 موفق و TLS سخت‌گیرانه روی ورودی HTTP به‌درستی ناموفق شد؛ Chrome نتیجه و محدودیت را نشان داد. قرارداد C30 و طراحی VLESS در D21 | این بررسی اثبات VLESS یا عبور دادهٔ کاربردی نیست. اجرای هسته و هویت آزمایشی VLESS منتظر تأیید مالک است. HTTP واقعیِ تونل در آزمون کاربردیِ جدا سنجیده شد. |
| WP8 | انجام‌شده با حدود آزمون مشخص | نصب دو عامل تازه روی Ubuntu24 amd64 با `/tmp` دارای noexec، رد checksum نادرست پیش از نصب، مقایسهٔ هویت، دانلود عین برنامه از nginx با TLS معتبر و شناسهٔ خطای429؛ Chrome انتظار/خطا/تأیید/فوکوس کیبورد را بررسی کرد | نصب‌کننده فقط معماری سازگارِ خود پنل را توزیع می‌کند. sudo تعاملیِ حساب غیرroot، ARM64 واقعی و SSH اختیاری آزمایش/پیاده‌سازی نشده‌اند. مراحل نصب ترمینال به‌عنوان پیشرفت قابل‌مشاهده در پنل جعل نمی‌شوند. |
| WP9 | انجام‌شده در دامنهٔ عیب‌های اثبات‌شده | رفع درخواست‌های هم‌زمانِ تکراری (۲ قبل/۱ بعد)، سبز ماندن پاسخ قدیمی در سه نما، فوکوس ثبت سرور، ترتیب FK، شناسهٔ نگاشت خام، پیام ثبت عملیات و متن پیش‌نمایش؛ آزمون‌های قبل/بعد موجودند | ادعای حذف همهٔ `any`ها یا بازآرایی کل برنامه وجود ندارد. |

## اجراهای قابل بررسی

| منبع | اجرای واقعی | نتیجه و محدوده |
|---|---|---|
| 6784238 | [Linux و Backhaul](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/39953493099) | موفقیت کامل مبنای Backhaul-only؛ TCP/WSS، systemd، مسیر HTTP، گواهی و بازیابی. این شاهد به‌تنهایی کد جدیدتر را تأیید نمی‌کند. |
| 4468290 | [ویرایش‌های واقعی و Chrome](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/39964707950) | هر چهار ویرایش و HTTP و پذیرش سرویس مشترک موفق؛ **کل اجرا ناموفق** به دلیل فرض غلط نسخهٔ مبنای تست. آزمون اکنون نسخهٔ واقعی ذخیره‌شده را می‌خواند؛ assertion بازگردانی حذف نشده است. |
| 5d508e | [ماتریس شکست](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/39973957040) | پورت، مقصد و توکن: ویرایش/HTTP، عدم تغییر در رد پیش‌بررسی، بازگشت دستی و شکست طرف دوم با تایمر واقعی ۹۰ثانیه موفق. **کل اجرا ناموفق**: گواهی عمومی سمت دوم برای WSS در آزمایش مستقر نشده بود؛ محیط تست اصلاح شد، guard حفظ شد. |
| b892551 | [ماتریس تکمیل‌شده](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40018277602) | هر چهار ویرایش: HTTP، رد پیش‌بررسی بدون تغییر، دو بکاپ، بازگشت دستی و تایمر واقعی ۹۰ثانیه موفق. **کل اجرا ناموفق**: فایل موقت آماده‌سازی CA آزمایش پیش از پایان boot ناپدید شد. آماده‌سازی CA اکنون پس از انتظار صریح پایان boot انجام می‌شود؛ TLS تضعیف نشده است. |
| 0c460de | [تعریف مشترک سلامت](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40018994404) | کل اجرا ناموفق، همان خطای آماده‌سازی CA پیش از پایان boot؛ هر چهار مورد ماتریس شکست موفق. نتیجهٔ ناموفق حفظ شده است. |
| 5480dab | [اجرای کامل موفق Linux](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40027781275)، [Verify](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40027781316) | **موفق**: Chrome واقعی، چهار ویرایش و HTTP، clone/lifecycle، پذیرش مشترک و بازگشت مبنا، گواهی و بازیابی، نصب تازه، چهار شکست/بازگشت90ثانیه. Go/native controller1177.99ثانیه و ماتریس436.38ثانیه. خروجی منتخب: [native](evidence/revision2/native-qualified-5480.txt)، [nginx/نصب/امنیت](evidence/revision2/verification-5480.txt). |
| c618421 | [گیت تاریخیِ کد مبنا](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40031275399)، [Verify](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40031275596) | **هر چهار گیت موفق**: native40031275399، Verify40031275596، نصب تمیز40031275554 و عیب‌یابی40031275471. اجرای یکپارچه1155.44ثانیه و ماتریس شکست427.60ثانیه. خروجی [native](evidence/revision2/native-qualified-c618.txt)، [nginx/نصب/امنیت](evidence/revision2/verification-c618.txt) و [شمارش رویدادهای کلیک](evidence/revision2/native-clicks-c618.json) موجود است. |
| d1230c8 | [نسخهٔ۰٫۸٫۰، Linux](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40071249185)، [انتشار](https://github.com/itsHesamHoseini/TunnelManager/actions/runs/40073441248) | هر چهار گیت و انتشار موفق؛ اجرای کنترلر۱۲۰۰٫۰۸ثانیه، ماتریس مستقل شکست۴۳۳٫۲۳ثانیه. [خروجی واقعی](evidence/revision2/native-qualified-d123.txt)، Chrome با منوی شش‌تایی و ویدئوی جاری؛ checksum هر دو فایل Linux با انتشار عمومی یکسان است. |

آزمون محلی با PostgreSQL جدا و Chrome واقعی: `npm run build --prefix web`، سپس `go test -p 1 ./... -count=1 -v` با `TEST_DATABASE_URL` آزمایشی و `TUNNELMANAGER_BROWSER_TESTS=1`. [خروجی واقعی محلی](evidence/revision2/local-tests.txt). آزمون‌های native دارای build tag روی Windows اجرا نمی‌شوند. اجرای Linux تکرارپذیر در `.github/workflows/engines.yml` است. شناسهٔ commitهای محلی و CI متفاوت است: درخت متن کد/آزمون/اسناد با index موقت تطبیق داده شده؛ تاریخچهٔ محلی حفظ شده است. PNGهای جدید محلی‌اند؛ شواهد native در artifact همان اجرا قرار می‌گیرند. اصلاح آخرِ رابط، خطای دریافت از پنل را به قطع عامل نسبت نمی‌دهد؛ این تغییر با آزمون مرورگرِ ناموفق قبل و موفق بعد ثبت شده؛ اجرای کامل منبع d1230c8 نیز شامل همین اصلاح با موفقیت پایان یافت.

## شمارنده‌ها و تعداد اقدام‌ها

| دامنهٔ اندازه‌گیری | قبل | بعد |
|---|---|---|
| دیتابیس مخلوطِ آزمایش مهاجرت | ۲ سرویس، ۲ تونل تحت مدیریت | ۱ سرویس، ۱ تونل تحت مدیریت؛ وابستگی‌های Backhaul حفظ شده |
| دیتابیس نمونهٔ Chrome پس از مهاجرت | ۲ سرویس، ۲ تونل مشاهده‌ای، ۰ تحت مدیریت | ۱ سرویس، ۱ تونل مشاهده‌ای، ۰ تحت مدیریت |
| طبقه‌بندی نمونهٔ WP3، قبل/بعد از پیش‌نمایش | ۲ قابل‌پذیرش، ۱ فقط‌خواندنی، ۱ بی‌جفت، ۰ تحت مدیریت | بدون تغییر؛ پیش‌نمایش مالکیت نمی‌گیرد |
| سرورهای پروداکشن مالک | در این اصلاح خوانده نشده | اندازه‌گیری‌نشده؛ هیچ پذیرش خودکار انجام نشده |

کلیک دکمه از فهرست تا تأیید اثر: پورت ورودی **۳**، مقصد **۳**، تغییر نوع ارتباط **۳**، تولید توکن تازه **۴** (دکمهٔ تولید جداست). تغییر مقدار فیلد/select جزو کلیک دکمه شمرده نشده است. تأیید ایمنی پس از اعمال، بازگشت به فهرست و آزمون مستقل اتصال جدا ثبت شده‌اند؛ این‌ها به‌قصد رسیدن به عدد ۳ حذف نشده‌اند. سه مرحلهٔ بازکردن/تغییر/بازبینی با «۳ کلیک کل عملیات» یکی نیست. بررسی سرور قطع‌شده از اقدام خانه: **۱ کلیک** در Chrome نمونه. یافتن تونل مشکل‌دار و دیدن لایهٔ ناموفق از خانه: **۱ کلیک** در Chrome نمونه با دریافت ساختگیِ خطای کاربردی و دو هویت متصل؛ شاهد خرابی موتور واقعی نیست.

## تصاویر و ویدئو

همهٔ تصاویر زیر از Chrome واقعی‌اند. «نمونه» یعنی API/دیتابیس محلی با دادهٔ ساختگی؛ شاهد اجرای موتور نیست.

- خانه، قبل: [۱۴۴۸](evidence/revision2/wp0-before-sample-1448.png)، [۱۹۲۰](evidence/revision2/wp0-before-sample-1920.png)، [موبایل](evidence/revision2/wp0-before-sample-390.png).
- خانه، بعد، نمونه، ابعاد دقیق viewport: [۱۴۴۸×۱۰۸۶](evidence/revision2/wp5-home-viewport-sample-1448.png)، [۱۹۲۰×۱۰۸۶](evidence/revision2/wp5-home-viewport-sample-1920.png)، [۳۹۰×۸۴۴](evidence/revision2/wp5-home-viewport-sample-390.png). نسخه‌های تمام‌صفحه با نام `wp5-home-sample-*` هم موجودند.
- فرم معمول، نمونه، ابعاد دقیق viewport: [۱۴۴۸×۱۰۸۶](evidence/revision2/wp2-normal-viewport-sample-1448.png)، [۱۹۲۰×۱۰۸۶](evidence/revision2/wp2-normal-viewport-sample-1920.png)، [موبایل](evidence/revision2/wp2-normal-viewport-sample-390.png)، [پیشرفته](evidence/revision2/wp2-advanced-sample.png)، [پیش‌نمایش تمام‌صفحه](evidence/revision2/wp2-preview-sample.png).
- [طبقه‌بندی نمونه](evidence/revision2/wp3-classification-sample-1448.png)، [تاریخچهٔ دارای شکاف، نمونه](evidence/revision2/wp6-gapped-history-sample.png)، [انتظار ثبت سرور، نمونه](evidence/revision2/wp8-waiting-sample-1448.png)، [ثبت عملیات فارسی، نمونه](evidence/revision2/wp0-audit-sample.png).
- علت خطای دریافت API در Chrome نمونه: [قبل، نسبت‌دادن نادرست به عامل](evidence/revision2/wp0-api-error-before-cause-sample.png)، [بعد، وضعیت عامل نامعلوم](evidence/revision2/wp0-api-error-sample.png). هیچ علت تازه‌ای دربارهٔ عامل بدون شاهد ساخته نمی‌شود.
- [راهنمای جایگزینی، نمونهٔ دسکتاپ](evidence/revision2/wp3-replacement-sample-1448.png)، [موبایل](evidence/revision2/wp3-replacement-sample-390.png)؛ زمان تعمیر در این نما برنامهٔ خواندنی است، نه عملیات زمان‌بندی‌شده.
- native نسخهٔ۰٫۸٫۰، منبع d1230c8: [جزئیات TCP فارسی](evidence/revision2/wp2-detail-tcp-native-d1230c8.png)، [پیش‌نمایش WSS](evidence/revision2/wp2-preview-wss-native-d1230c8.png)، [موبایل](evidence/revision2/wp2-mobile-native-d1230c8.png). خلاصه و نقشهٔ پیشنهادی در تصویر جدید مقصد29096 را درست نشان می‌دهند؛ تصاویر قدیمی4468290 فقط شاهد تاریخی‌اند.
- ویدئوی ویرایش پورت واقعی: artifact `native-browser-evidence` اجرای40071249185، فایل `revision2/wp2-port-edit-native.webm` (۶٫۵MB). SHA256 آرشیوa2705a9c9a1a0cbec577d8073e8350e8f244b5fd6794726363cebc7b810c05d6 تأیید شد؛ کل اجرا موفق است. ورود، رمز و MFA ضبط نشده‌اند.

## تصمیم‌ها و محدودیت‌های باز

تنظیمات معمول، چندردیفی‌بودن نگاشت و پیش‌فرض مقصد طبق پاسخ مالک قطعی است. چهار تصمیم معماری/عملیاتی هنوز بازند: سرنوشت سرویس قدیمی روی میزبان، SSH یک‌بارمصرف، هویت/هستهٔ آزمایشی VLESS، مدل دسترسی عامل. تا پاسخ، معماری و سطح دسترسی موجود تغییر نمی‌کنند؛ موتور کنارگذاشته‌شده روی میزبان حذف نمی‌شود. پیشنهادهای D21/D22/D23 پیاده‌سازی نیستند.

WP4 با درخواست تازهٔ «تکمیل باقی‌مانده و انتشار» اجرا شد: مسیرها + تونل‌ها + کشف زیر «تونل‌ها»؛ سرویس/پورت/برچسب/مانیتورینگ زیر ابزارهای پیشرفتهٔ سرورها؛ عملیات + هشدار در یک بخش؛ امنیت زیر تنظیمات؛ گواهی‌ها مستقل. [نقشهٔ کامل نشانی‌ها](NAVIGATION-MAP.md) و [شاهد مرورگر](evidence/revision2/navigation-080.txt) موجودند. هیچ قابلیت Backhaul حذف نشده است.

کانفیگ واقعی پوشیده‌شده برای corpus درخواست شده است. ارائه‌نشدن آن، مانع ادامهٔ آزمون‌های مصنوعی/native نیست، اما ادعای پوشش سرورهای واقعی را نامعتبر می‌کند. ACME/DNS و Telegram با حساب واقعی مالک، ARM64 واقعی، Debian11 و VLESS آزمایش نشده‌اند. نصب عامل با sudo تعاملی از حساب غیرroot در مسیر bootstrap جدید نیز تا شاهد جداگانه آزمایش‌نشده محسوب می‌شود.

`node scripts/supported-engine.mjs` باید صفر نتیجهٔ غیرمجاز و دقیقاً ۳ تطبیق مجاز (۲ مورد در فایل مهاجرت، ۱ یادداشت حذف در RELEASE-NOTES) بدهد. `node scripts/neutrality.mjs` و `node scripts/secrets.mjs` پیش از commit/push اجرا شده‌اند؛ اسکن کامل gitleaks تاریخچه نیز بدون افشای محتوا موفق بود. نتیجهٔ build، مدرک کامل‌بودن محصول یا مجوز استقرار نیست.

در خروجی واقعی govulncheck مرجعc618، تعداد نمادها و بسته‌های واردشدهٔ آسیب‌پذیر صفر است؛ یک هشدار در سطح ماژول دربارهٔ بستهٔ استفاده‌نشدهٔ OpenPGP در x/crypto نیز ثبت شده و پنهان نشده است. `go list -deps ./cmd/tunnelmanager` برای کد نهایی296 بسته و صفر import مربوط به OpenPGP نشان داد. این نتیجه ادعای «تمام وابستگی‌ها بدون هیچ هشدار» نیست؛ [خروجی ابزار](evidence/revision2/verification-c618.txt) مرجع است.

## محل پیاده‌سازی و آزمون

| بسته | فایل‌های اصلی | شاهد قابل تکرار |
|---|---|---|
| WP0 | [نمایش مشترک](../web/src/presentation.tsx)، [پیام/پاسخ قدیمی](../web/src/operations.tsx)، [تعریف مشاهده](../internal/controller/observation.go)، [nginx](../internal/deploy/templates/nginx.conf) | `TestRevisionHonestyBrowser`، `TestObservationTruth`، `TestTunnelHealthUsesAuthoritativeNodeAvailability`، `TestRequestIDErrorContract`، Compose429 |
| WP1 | مهاجرت5 در controller، [بکاپ](../internal/controller/retirement_backup.go)، [آزمون مهاجرت](../internal/controller/retirement_test.go) | `TestRetirement*`، `TestUnknownActualListenerStillBlocksPort`، source gate و native TCP/WSS |
| WP2 | [فرم](../web/src/backhaul-editor.tsx)، [مدل](../web/src/backhaul-model.ts)، [API](../internal/controller/editor.go)، [پروتکل اعمال](../internal/controller/tunnels.go) | `TestSimpleEditorChrome`، `TestDraftNormalizationIsReadOnlyRevisionCheckedAndRedacted`، `TestNativeOrdinaryEditFailureMatrix` و Chrome native |
| WP3 | [قانون پذیرش](../internal/controller/adoption.go)، [رابط](../web/src/adoption.tsx)، [برنامهٔ جایگزینی](../web/src/replacement-guide.tsx) | `TestAdoptionDryRunAndReportPreserveInfrastructureBoundary` و مسیر کشف/پذیرش/ویرایش/بازگشت در `TestNativeControllerBrowserWorkflow` |
| WP4 | [نقشهٔ اجراشده](NAVIGATION-MAP.md)، [مسیریابی](../web/src/navigation.ts) | `verifyNavigation`، نشانی‌های قدیمی، Back و فرم ذخیره‌نشده در Chrome؛ گردش‌های native |
| WP5 | [خانه](../web/src/home.tsx)، [کنسول](../web/src/console.tsx) | `TestRevisionHonestyBrowser`؛ عرض/سرستون/یک کلیک |
| WP6 | [نمودار مشاهدات](../web/src/observed-history.tsx)، [لایه‌ها](../web/src/health-layers.tsx)، [تجمیع](../internal/controller/retention.go) | `TestDayHistoryIsBoundedMeasuredBucketsWithMissingValues`، Chrome و نمونه‌های native |
| WP7 | [آزمون ورودی](../internal/controller/entry_check.go)، [رابط](../web/src/entry-check.tsx)، تصمیم D21 | تست‌های [entry_check_test.go](../internal/controller/entry_check_test.go) و TCP موفق/TLS منفی native |
| WP8 | [دریافت برنامه](../internal/controller/bootstrap.go)، [اسکریپت ثابت](../internal/controller/node_bootstrap.sh)، [رابط](../web/src/enrollment.tsx) | `TestBootstrap*`، `TestLiveEnrollmentChrome`، `TestEnrollmentStatusBindsOnlyConsumedIdentity`، نصب تازه native و دانلود از edge |
| WP9 | فایل‌های بالا و [متن واقعی فرم](FORM-COPY.fa.md) | شکست قبل/موفقیت بعد در خروجی آزمون و شرح دقیق در PROGRESS؛ بدون بازنویسی گسترده |

خروجی‌های محلی ساخت Linux برای amd64 و arm64 در `artifacts/`، همراه SHA256SUMS، از commit نهایی معرفی‌شده در `artifacts/BUILD-INFO.json` ساخته شده‌اند. ساخت arm64، آزمون اجرای arm64 نیست. فایل‌های دقیق منبع d1230c8 در انتشار۰٫۸٫۰ منتشر شده‌اند و checksum عمومی با ساخت محلی همان منبع یکسان است. ساخت نهاییِ انتشار در `.runtime/release080-source/artifacts/` نیز موجود است؛ فایل‌های `artifacts/` و manifest آن نیز به همین نسخهٔ منتشرشده به‌روز شده‌اند.
