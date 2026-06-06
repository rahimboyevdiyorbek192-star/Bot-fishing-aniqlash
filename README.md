# 🛡 Fishing Aniqlagich Bot

Telegram havolalarini professional darajada tekshiradigan kiberxavfsizlik boti.

---

## ⚡ Tezkor o'rnatish

### Windows
1. `install.bat` ni 2 marta bosing
2. `.env` faylni oching, `BOT_TOKEN` ni kiriting
3. `start.bat` ni ishga tushiring

### Linux / Mac
```bash
bash install.sh
nano .env      # BOT_TOKEN ni kiriting
bash start.sh
```

---

## 🔧 .env sozlamalari

`.env.example` faylini `.env` nomi bilan ko'chiring va to'ldiring:

| O'zgaruvchi | Tavsif | Majburiy |
|---|---|---|
| `BOT_TOKEN` | @BotFather dan olingan token | ✅ Ha |
| `VIRUSTOTAL_API_KEY` | virustotal.com — bepul | Tavsiya |
| `ABUSEIPDB_API_KEY` | abuseipdb.com — bepul | Tavsiya |
| `TELETHON_API_ID` | my.telegram.org/apps | Ixtiyoriy |
| `TELETHON_API_HASH` | my.telegram.org/apps | Ixtiyoriy |
| `TELETHON_SESSION` | Session string (quyida ko'rsatilgan) | Ixtiyoriy |

---

## 🤖 Userbot (Telethon) ulash — ixtiyoriy

Userbot shubhali botlarga `/start` yuborib, javobdagi yashirin havolalarni topadi.

**1. my.telegram.org/apps ga kiring → App yarating → API ID va Hash oling**

**2. Session string yarating:**
```bash
python3 -c "
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
c = TelegramClient(StringSession(), 12345678, 'sizning_api_hash')
c.start()
print('SESSION:', c.session.save())
"
```

Chiqgan `SESSION:` qatorini `.env` dagi `TELETHON_SESSION=` ga joylashtiring.

---

## 🔍 Bot nima tekshiradi?

| Tekshiruv | Tavsif |
|---|---|
| 🦠 VirusTotal | 70+ antivirus va threat intelligence |
| ☣️ URLhaus | abuse.ch malware/phishing bazasi |
| 🚨 AbuseIPDB | Spam va hujum IP reputatsiyasi |
| 🛡 SSL | Sertifikat holati va muddati |
| 📅 WHOIS | Domen yoshi va ro'yxatdan o'tgan sana |
| 🔗 Redirect | Yo'naltirish zanjiri har bir qadam |
| 🌐 Brauzer | Playwright — JS redirect, karta/parol shakli |
| 🤖 Userbot | Botga `/start` yuborib javobdagi URL lar |
| 🔤 Homograf | Unicode Kirill/Grek harflar orqali aldash |
| 🇺🇿 Brend | O'zbek va global brendlar taqlidi |
| 📱 Telegram | Kanal tasdiqlanganligi, a'zolar soni |

---

## 📊 Xavf darajasi

| Ball | Daraja |
|---|---|
| 0–25 | 🟢 Xavfsiz |
| 26–50 | 🟡 Shubhali |
| 51–75 | 🟠 Xavfli |
| 76–100 | 🔴 JUDA XAVFLI |
