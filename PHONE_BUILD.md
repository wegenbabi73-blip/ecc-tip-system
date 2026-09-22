# ECC Tip System — በስልክ ብቻ APK ማዘጋጀት

ይህ ፕሮጀክት GitHub Actions workflow ይዟል። ስለዚህ Android Studio በስልክ ላይ መጫን አያስፈልግም።

## 1. ZIP ን አውጣ
በስልክ ላይ ZIP-ውን አውርደህ ወደ GitHub repository ላይ ፋይሎቹን ጫን።

## 2. GitHub ላይ Workflow አስነሳ
Repository → **Actions** → **Build ECC Tip System APK** → **Run workflow**.

## 3. APK አውርድ
Build ከተጠናቀቀ በኋላ workflow run ውስጥ **Artifacts** → `ecc-tip-system-debug-apk` → Download.

## 4. በAndroid ላይ ጫን
ZIP/Artifact ን አውጣ፣ `app-debug.apk` ን ክፈት፣ Android ከጠየቀ የbrowser/file manager የAPK installation permission ፍቀድ።

### አስፈላጊ
APK የmobile client ነው። የserver/backend ክፍል ከስልኩ ውጭ በHTTPS ላይ እንዲሰራ ማስተናገድ ያስፈልጋል። `www/api.js` ውስጥ `ecc_api_base` በlocalStorage በመያዝ API URL ማዋቀር ይቻላል።
