import os
import ssl
import socket
import sqlite3
import urllib.parse
import datetime
import requests
import whois
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

DB_PATH = "stats.db"

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".su", ".icu", ".live"}
SUSPICIOUS_COUNTRIES = {"Russia", "China", "North Korea", "Iran", "Belarus"}
SHORT_URL_DOMAINS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "short.link", "rebrand.ly", "cutt.ly", "clck.ru", "vk.cc"}


# --- Ma'lumotlar bazasi ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            url       TEXT,
            risk      INTEGER,
            checked   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_stat(url: str, risk: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO stats (url, risk) VALUES (?, ?)", (url, risk))
    conn.commit()
    conn.close()

def get_stats() -> tuple[int, int]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT COUNT(*), SUM(CASE WHEN risk >= 50 THEN 1 ELSE 0 END) FROM stats"
    ).fetchone()
    conn.close()
    return (row[0] or 0), (row[1] or 0)


# --- Tahlil yordamchi funksiyalar ---

def expand_short_url(url: str) -> tuple[str, bool]:
    """Qisqa havolani ochib, asl manzilni qaytaradi."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        if domain in SHORT_URL_DOMAINS:
            resp = requests.head(url, allow_redirects=True, timeout=5)
            if resp.url and resp.url != url:
                return resp.url, True
    except Exception:
        pass
    return url, False

def check_ssl(domain: str) -> dict:
    """SSL sertifikat holati va muddatini tekshiradi."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expire - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "valid": True,
            "days_left": days_left,
            "issuer": issuer.get("organizationName", "Noma'lum"),
        }
    except Exception:
        return {"valid": False, "days_left": 0, "issuer": "Noma'lum"}

def check_whois(domain: str) -> dict:
    """Domen yoshi va registratorini aniqlaydi."""
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.datetime.utcnow() - created).days
            return {"age_days": age, "registrar": w.registrar or "Noma'lum"}
    except Exception:
        pass
    return {"age_days": None, "registrar": "Noma'lum"}

def calculate_risk(domain: str, country: str, ssl_info: dict, whois_info: dict, redirected: bool) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    tld = "." + domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"⚠️ Shubhali domen kengaytmasi: `{tld}`")

    if country in SUSPICIOUS_COUNTRIES:
        score += 20
        reasons.append(f"⚠️ Server {country}da joylashgan")

    if not ssl_info["valid"]:
        score += 25
        reasons.append("⚠️ SSL sertifikat yo'q yoki yaroqsiz")
    elif ssl_info["days_left"] < 30:
        score += 10
        reasons.append(f"⚠️ SSL sertifikat {ssl_info['days_left']} kun ichida tugaydi")

    age = whois_info["age_days"]
    if age is not None:
        if age < 180:
            score += 30
            reasons.append(f"⚠️ Domen yaqinda ro'yxatdan o'tgan ({age} kun avval)")
        elif age < 365:
            score += 15
            reasons.append(f"⚠️ Domen nisbatan yangi ({age} kun avval)")

    if redirected:
        score += 10
        reasons.append("⚠️ Qisqa havola — asl manzil yashirilgan edi")

    return min(score, 100), reasons

def risk_label(score: int) -> str:
    if score <= 25:
        return "🟢 Xavfsiz"
    elif score <= 50:
        return "🟡 Shubhali"
    elif score <= 75:
        return "🟠 Xavfli"
    else:
        return "🔴 JUDA XAVFLI"

def format_age(days: int | None) -> str:
    if days is None:
        return "Noma'lum"
    if days >= 365:
        return f"{days // 365} yil {(days % 365) // 30} oy"
    return f"{days} kun"


# --- Asosiy tahlil funksiyasi ---

def analyze_url(url: str) -> tuple[str, int]:
    try:
        expanded_url, redirected = expand_short_url(url)

        parsed = urllib.parse.urlparse(expanded_url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        if not domain:
            return None, 0

        ip = socket.gethostbyname(domain)
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        country = geo.get("country", "Noma'lum")
        isp = geo.get("isp", "Noma'lum")
        org = geo.get("org", "Noma'lum")

        ssl_info = check_ssl(domain)
        whois_info = check_whois(domain)
        score, reasons = calculate_risk(domain, country, ssl_info, whois_info, redirected)
        label = risk_label(score)

        ssl_str = (
            f"✅ Ha ({ssl_info['days_left']} kun qoldi · {ssl_info['issuer']})"
            if ssl_info["valid"] else "❌ Yo'q"
        )
        redirect_str = f"🔀 Ha → `{expanded_url}`" if redirected else "✅ Yo'q"

        report = (
            f"🔍 **Havola tahlili:**\n"
            f"🌐 **Domen:** `{domain}`\n"
            f"📌 **IP Manzil:** `{ip}`\n"
            f"🌍 **Server joylashuvi:** {country}\n"
            f"🏢 **Hosting:** {isp}\n"
            f"🔒 **Tashkilot:** {org}\n"
            f"🛡 **SSL sertifikat:** {ssl_str}\n"
            f"📅 **Domen yoshi:** {format_age(whois_info['age_days'])} · {whois_info['registrar']}\n"
            f"🔗 **Yo'naltirish:** {redirect_str}\n"
            f"\n📊 **Xavf darajasi: {score}/100 — {label}**\n"
        )

        if reasons:
            report += "\n**Ogohlantirish sabablari:**\n" + "\n".join(reasons)

        return report, score

    except Exception:
        return (
            f"🌐 **Domen:** `{url}`\n"
            f"❌ *Ma'lumot olib bo'lmadi yoki domen bloklangan.*"
        ), 0


# --- Botning komanda handlerlari ---

@dp.message(Command("start", "help"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🛡 **Fishing Aniqlagich Bot**\n\n"
        "Bu bot Telegram xabarlaridagi havolalarni tekshirib, "
        "ular xavfli yoki xavfsizligini aniqlaydi.\n\n"
        "**Qanday foydalanish:**\n"
        "• Shubhali xabarni menga *forward* qiling\n"
        "• Yoki to'g'ridan-to'g'ri havola yuboring\n"
        "• Bot avtomatik tahlil qilib natija beradi\n\n"
        "**Bot nima tekshiradi?**\n"
        "🌍 Server joylashuvi va hosting\n"
        "🛡 SSL sertifikat holati va muddati\n"
        "📅 Domen yoshi — yangi domenlar ko'proq xavfli\n"
        "🔗 Qisqa havolalarning asl manzili\n"
        "📊 Umumiy xavf darajasi (0–100 ball)\n\n"
        "**Buyruqlar:**\n"
        "/start — Bosh sahifa\n"
        "/stats — Statistika\n\n"
        "⚠️ Xavf darajasi yuqori bo'lsa, o'sha havolaga "
        "hech qachon karta yoki shaxsiy ma'lumot kiritmang!",
        parse_mode="Markdown",
    )

@dp.message(Command("stats"))
async def cmd_stats(message: types.Message):
    total, dangerous = get_stats()
    safe = total - dangerous
    await message.answer(
        f"📊 **Bot statistikasi:**\n\n"
        f"🔍 Jami tekshirilgan: **{total}** ta havola\n"
        f"🔴 Xavfli (≥50 ball): **{dangerous}** ta\n"
        f"🟢 Xavfsiz (<50 ball): **{safe}** ta",
        parse_mode="Markdown",
    )


# --- Asosiy xabar handleri ---

@dp.message()
async def handle_message(message: types.Message):
    urls_to_check: set[str] = set()

    text = message.text or message.caption or ""

    entities = message.entities or message.caption_entities or []
    for entity in entities:
        if entity.type == "url":
            url = text[entity.offset : entity.offset + entity.length]
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            urls_to_check.add(url)
        elif entity.type == "text_link" and entity.url:
            urls_to_check.add(entity.url)

    if message.reply_markup and hasattr(message.reply_markup, "inline_keyboard"):
        for row in message.reply_markup.inline_keyboard:
            for button in row:
                if button.url:
                    urls_to_check.add(button.url)

    if not urls_to_check:
        await message.reply(
            "⚠️ Ushbu xabarda hech qanday havola yoki yashirin tugma topilmadi."
        )
        return

    await message.reply("⏳ Havolalar tahlil qilinmoqda, biroz kuting...")

    final_response = "🚨 **Kiberxavfsizlik tahlil hisoboti:**\n\n"
    for url in urls_to_check:
        result, score = analyze_url(url)
        if result:
            save_stat(url, score)
            final_response += result + "\n" + "—" * 22 + "\n"

    final_response += (
        "\n⚠️ **Eslatma:** Xavf darajasi 50 dan yuqori bo'lsa, "
        "u havolaga plastik karta yoki shaxsiy ma'lumotlaringizni MUTLAQO kiritmang!"
    )

    await message.reply(final_response, parse_mode="Markdown")


if __name__ == "__main__":
    init_db()
    print("Bot ishga tushdi...")
    dp.run_polling(bot)
