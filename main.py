import os
import ssl
import socket
import sqlite3
import base64
import unicodedata
import urllib.parse
import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

import requests
import whois
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
executor = ThreadPoolExecutor(max_workers=10)

DB_PATH = "stats.db"

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".su", ".icu", ".live", ".online", ".site", ".fun", ".space"
}
SUSPICIOUS_COUNTRIES = {"Russia", "China", "North Korea", "Iran", "Belarus"}
SHORT_URL_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
    "rebrand.ly", "cutt.ly", "clck.ru", "vk.cc"
}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "bank",
    "payment", "signin", "password", "credential", "recover", "wallet",
    "billing", "kirish", "tasdiqlash", "xavfsiz", "hisob", "karta"
}
# Telegram ichidagi ijtimoiy muhandislik so'zlari
SCAM_BUTTON_WORDS = {
    "bonus", "sovg'a", "yutdi", "prize", "olish", "win", "gift",
    "бонус", "приз", "получить", "награда", "free", "tekin", "bepul",
    "yutuq", "lotereya", "lottery", "jackpot", "cash", "money"
}
TELEGRAM_DOMAINS = {"t.me", "telegram.me", "telegram.dog"}
UZBEK_BRANDS = {
    "payme": "payme.uz",
    "click": "click.uz",
    "uzcard": "uzcard.uz",
    "humo": "humo.uz",
    "kapitalbank": "kapitalbank.uz",
    "hamkorbank": "hamkorbank.uz",
    "myuzcard": "myuzcard.uz",
    "davrbank": "davrbank.uz",
    "aloqabank": "aloqabank.uz",
    "nbu": "nbu.uz",
}
GLOBAL_BRANDS = {
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "telegram": "telegram.org",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
}
ALL_BRANDS = {**UZBEK_BRANDS, **GLOBAL_BRANDS}


# ── Ma'lumotlar bazasi ──────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            url     TEXT,
            risk    INTEGER,
            checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


# ── Tarmoq tekshiruvlari ────────────────────────────────────────────────────

def get_redirect_chain(url: str) -> list[str]:
    """Har bir yo'naltirish qadamini ko'rsatadi."""
    chain = []
    current = url
    try:
        for _ in range(10):
            resp = requests.get(current, allow_redirects=False, timeout=5, stream=True)
            chain.append(current)
            if resp.is_redirect and resp.headers.get("Location"):
                nxt = resp.headers["Location"]
                if not nxt.startswith("http"):
                    p = urllib.parse.urlparse(current)
                    nxt = f"{p.scheme}://{p.netloc}{nxt}"
                current = nxt
            else:
                break
    except Exception:
        pass
    return chain if chain else [url]

def check_ssl(domain: str) -> dict:
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
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if isinstance(created, str):
                created = datetime.datetime.fromisoformat(created)
            age = (datetime.datetime.utcnow() - created).days
            return {"age_days": age, "registrar": w.registrar or "Noma'lum"}
    except Exception:
        pass
    return {"age_days": None, "registrar": "Noma'lum"}

def _get_geo(ip: str) -> dict:
    try:
        return requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
    except Exception:
        return {}

def check_virustotal(url: str) -> dict:
    if not VT_API_KEY:
        return {"available": False}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats:
                return {
                    "available": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total": sum(stats.values()),
                }
        # URL hali tahlil qilinmagan — topshiramiz
        sub = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=10
        )
        if sub.status_code == 200:
            return {"available": True, "malicious": 0, "suspicious": 0, "total": 0, "pending": True}
    except Exception:
        pass
    return {"available": False}

def check_urlhaus(url: str) -> dict:
    """URLhaus (abuse.ch) — malware/phishing URL bazasi. API kalit shart emas."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=10
        ).json()
        status = resp.get("query_status", "")
        if status == "is_available":
            return {
                "available": True,
                "found": True,
                "threat": resp.get("threat", "malware"),
                "tags": resp.get("tags") or [],
            }
        return {"available": True, "found": False, "threat": "", "tags": []}
    except Exception:
        return {"available": False}

def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY or ip == "Noma'lum":
        return {"available": False}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=8
        ).json()
        data = resp.get("data", {})
        return {
            "available": True,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
        }
    except Exception:
        return {"available": False}

async def check_with_browser(url: str) -> dict:
    """Headless Chromium orqali URL ni ochib, haqiqiy manzil va sahifa ma'lumotlarini oladi."""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            ctx = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )
            page = await ctx.new_page()

            try:
                await page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                # networkidle kutmasa ham sahifa ochilgan bo'lishi mumkin
                pass

            final_url = page.url
            title = await page.title()

            # Shubhali shakllar bor-yo'qligini tekshiramiz
            has_password  = await page.locator("input[type='password']").count() > 0
            has_card_input = await page.locator(
                "input[name*='card'], input[placeholder*='card'], "
                "input[placeholder*='karta'], input[name*='pan'], "
                "input[maxlength='16'], input[maxlength='19']"
            ).count() > 0
            has_form = await page.locator("form").count() > 0

            await browser.close()

            return {
                "available": True,
                "final_url": final_url,
                "title": title[:120],
                "redirected": final_url.rstrip("/") != url.rstrip("/"),
                "has_password": has_password,
                "has_card_input": has_card_input,
                "has_form": has_form,
            }
    except ImportError:
        return {"available": False, "error": "playwright o'rnatilmagan"}
    except Exception as e:
        return {"available": False, "error": str(e)[:100]}


# ── Heuristik tekshiruvlar ──────────────────────────────────────────────────

def check_url_patterns(url: str, domain: str) -> list[str]:
    warnings = []

    # To'g'ridan IP manzil
    try:
        socket.inet_aton(domain)
        warnings.append("⚠️ Domain o'rniga IP manzil ishlatilgan")
    except socket.error:
        pass

    # @ belgisi — manzil yashirish hiylasi
    if "@" in url:
        warnings.append("⚠️ URL da `@` belgisi — asl manzil yashirilgan bo'lishi mumkin")

    # Shubhali kalit so'zlar
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found:
        warnings.append(f"⚠️ Shubhali so'zlar URL da: `{', '.join(found[:4])}`")

    # Haddan ko'p subdomen
    parts = domain.split(".")
    if len(parts) > 4:
        warnings.append(f"⚠️ Ko'p subdomen: {len(parts) - 2} ta")

    # Juda uzun URL
    if len(url) > 150:
        warnings.append(f"⚠️ URL juda uzun: {len(url)} ta belgi")

    # Ko'p chiziqcha
    if domain.count("-") >= 2:
        warnings.append("⚠️ Domenda ko'p `-` — phishing belgisi")

    return warnings

def check_brand_impersonation(domain: str) -> list[str]:
    warnings = []
    dl = domain.lower()
    for brand, official in ALL_BRANDS.items():
        if brand in dl and dl != official and not dl.endswith("." + official):
            tag = "🇺🇿" if brand in UZBEK_BRANDS else "🌐"
            warnings.append(f"⚠️ {tag} `{brand}` brendini taqlid qilishi mumkin! Rasmiy: `{official}`")
    return warnings

def check_homograph(domain: str) -> list[str]:
    found = []
    for ch in domain:
        if ch in ".-0123456789":
            continue
        name = unicodedata.name(ch, "")
        if any(s in name for s in ("CYRILLIC", "GREEK", "ARABIC", "ARMENIAN")):
            found.append(ch)
    if found:
        return [f"⚠️ Homograf hujum! Unicode harflar aniqlandi: `{''.join(set(found))}`"]
    return []

def check_telegram_url(url: str) -> list[str]:
    """t.me/username — path ichida brend taqlid borligini tekshiradi."""
    warnings = []
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc not in TELEGRAM_DOMAINS:
        return warnings
    path = parsed.path.strip("/").lower().replace("_", "").replace("-", "")
    if not path or path.startswith("+"):
        if path.startswith("+"):
            warnings.append("⚠️ Yopiq Telegram kanal taklifi — ehtiyot bo'ling")
        return warnings
    for brand in ALL_BRANDS:
        brand_clean = brand.replace("_", "").replace("-", "")
        if brand_clean in path:
            tag = "🇺🇿" if brand in UZBEK_BRANDS else "🌐"
            warnings.append(
                f"⚠️ {tag} Telegram username `{brand}` brendini taqlid qilishi mumkin: `t.me/{parsed.path.strip('/')}`"
            )
    return warnings

async def check_telegram_channel(url: str) -> dict:
    """Telegram Bot API orqali kanal/bot haqida haqiqiy ma'lumot oladi."""
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc not in TELEGRAM_DOMAINS:
        return {}

    path = parsed.path.strip("/")
    if not path:
        return {}

    # Yopiq kanal taklifi (t.me/+xxx)
    if path.startswith("+"):
        return {"is_private_invite": True}

    # Username olish (start parametrlarini tashlaymiz)
    username = path.split("?")[0].split("/")[0]
    if not username:
        return {}

    try:
        chat = await bot.get_chat(f"@{username}")
        title = chat.title or getattr(chat, "full_name", "") or ""
        description = chat.description or ""

        title_lower = title.lower().replace(" ", "").replace("_", "").replace("-", "")
        title_homograph = any(
            any(s in unicodedata.name(ch, "") for s in ("CYRILLIC", "GREEK"))
            for ch in title if ch.isalpha()
        )

        brand_in_title = []
        for brand in ALL_BRANDS:
            brand_clean = brand.replace("_", "").replace("-", "")
            if brand_clean in title_lower:
                brand_in_title.append(brand)

        return {
            "found": True,
            "username": chat.username or username,
            "chat_type": chat.type,
            "title": title,
            "verified": getattr(chat, "is_verified", False),
            "member_count": getattr(chat, "member_count", None),
            "description": description[:200],
            "brand_in_title": brand_in_title,
            "title_has_homograph": title_homograph,
        }
    except Exception:
        # Bot/kanal topilmadi — o'chirilgan yoki maxfiy
        # Bu o'zi katta ogohlantirish: spam yuborib o'chirib ketishgan
        return {"found": False, "username": username, "deleted": True}

def check_message_context(message: types.Message) -> list[str]:
    """Xabar tuzilmasidan fishing belgilarini topadi (forward, tugma matnlari)."""
    warnings = []

    # Forward tekshiruvi
    if message.forward_date:
        # @PostBot orqali forward — asl manbani yashirish uchun ishlatiladi
        if message.forward_sender_name:
            name_lower = message.forward_sender_name.lower()
            if "postbot" in name_lower or "post bot" in name_lower:
                warnings.append("⚠️ @PostBot orqali forward — asl manba ataylab yashirilgan")
            # Brend taqlid in sender name
            for brand in ALL_BRANDS:
                if brand in name_lower:
                    warnings.append(f"⚠️ Forward yuboruvchi nomi `{brand}` brendini taqlid qilishi mumkin")
                    break

        if message.forward_from_chat:
            title = (message.forward_from_chat.title or "").lower()
            # Cyrillic brend nomlari (КАПИТАЛ, ХУМО va h.k.)
            for brand in ALL_BRANDS:
                if brand in title:
                    tag = "🇺🇿" if brand in UZBEK_BRANDS else "🌐"
                    warnings.append(
                        f"⚠️ {tag} Forward kanal/guruh nomi `{brand}` brendini taqlid qilishi mumkin"
                    )
                    break
            # Tasdiqlanmagan kanal
            if not message.forward_from_chat.username:
                warnings.append("⚠️ Forward manba — nomi yo'q yashirin kanal")

    # Inline tugma matni va WebApp tekshiruvi
    if message.reply_markup and hasattr(message.reply_markup, "inline_keyboard"):
        for row in message.reply_markup.inline_keyboard:
            for btn in row:
                if btn.text:
                    btn_lower = btn.text.lower()
                    found = [kw for kw in SCAM_BUTTON_WORDS if kw in btn_lower]
                    if found:
                        warnings.append(
                            f"⚠️ Tugma matni ijtimoiy muhandislik: '{btn.text}'"
                        )
                # WebApp tugmasi — havola Telegram ichida yashiringan
                if btn.web_app and btn.web_app.url:
                    warnings.append(
                        f"⚠️ WebApp tugmasi — havola yashiringan: `{btn.web_app.url[:80]}`"
                    )

    return warnings


# ── Xavf hisoblash ──────────────────────────────────────────────────────────

def calculate_risk(
    domain: str, country: str,
    ssl_info: dict, whois_info: dict, redirected: bool,
    vt: dict, urlhaus: dict, abuse: dict,
    pattern_w: list, brand_w: list, homograph_w: list,
    tg_url_w: list = None, context_w: list = None,
) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    if vt.get("available") and not vt.get("pending") and vt.get("malicious", 0) > 0:
        score += min(vt["malicious"] * 5, 40)
        reasons.append(f"🔴 VirusTotal: {vt['malicious']}/{vt['total']} engine xavfli dedi")

    if urlhaus.get("found"):
        score += 40
        threat = urlhaus.get("threat", "malware")
        reasons.append(f"🔴 URLhaus: bazada topildi — `{threat}`")

    if abuse.get("available") and abuse.get("abuse_score", 0) > 25:
        score += min(abuse["abuse_score"] // 4, 20)
        reasons.append(f"🔴 AbuseIPDB: {abuse['abuse_score']}/100 ({abuse.get('total_reports', 0)} shikoyat)")

    if homograph_w:
        score += 35
        reasons.extend(homograph_w)

    if brand_w:
        score += 25
        reasons.extend(brand_w)

    # Telegram havola: brend taqlid yoki o'chirilgan kanal
    if tg_url_w:
        # O'chirilgan kanal — juda kuchli belgi
        deleted = any("O'CHIRILGAN" in w for w in tg_url_w)
        score += 45 if deleted else 30
        reasons.extend(tg_url_w)

    # Xabar konteksti: forward, tugma matni
    if context_w:
        score += min(len(context_w) * 15, 35)
        reasons.extend(context_w)

    tld = "." + domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"⚠️ Shubhali kengaytma: `{tld}`")

    if country in SUSPICIOUS_COUNTRIES:
        score += 20
        reasons.append(f"⚠️ Server {country}da joylashgan")

    if not ssl_info["valid"]:
        score += 25
        reasons.append("⚠️ SSL sertifikat yo'q yoki yaroqsiz")
    elif ssl_info["days_left"] < 30:
        score += 10
        reasons.append(f"⚠️ SSL {ssl_info['days_left']} kun ichida tugaydi")

    age = whois_info.get("age_days")
    if age is not None:
        if age < 180:
            score += 30
            reasons.append(f"⚠️ Domen {age} kun oldin ro'yxatdan o'tgan — juda yangi")
        elif age < 365:
            score += 15
            reasons.append(f"⚠️ Domen nisbatan yangi ({age} kun)")

    if redirected:
        score += 10
        reasons.append("⚠️ Yashirin yo'naltirish aniqlandi")

    if pattern_w:
        score += min(len(pattern_w) * 8, 25)
        reasons.extend(pattern_w)

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


# ── Asosiy tahlil (parallel) ────────────────────────────────────────────────

async def analyze_url(url: str, context_w: list = None) -> tuple[str, int]:
    loop = asyncio.get_event_loop()

    try:
        # 1. Yo'naltirish zanjiri
        chain = await loop.run_in_executor(executor, get_redirect_chain, url)
        final_url = chain[-1] if chain else url
        redirected = len(chain) > 1

        parsed = urllib.parse.urlparse(final_url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        if "@" in domain:
            domain = domain.split("@")[-1]
        if not domain:
            return None, 0

        # 2. Tezkor heuristikalar (tarmoqsiz)
        pattern_w = check_url_patterns(final_url, domain)
        brand_w = check_brand_impersonation(domain)
        homograph_w = check_homograph(domain)
        tg_url_w = check_telegram_url(final_url)

        # 2a. t.me havolasi — Telegram API orqali kanal ma'lumotlarini olish
        is_telegram_link = domain in TELEGRAM_DOMAINS
        tg_channel = {}
        if is_telegram_link:
            tg_channel = await check_telegram_channel(final_url)

        # t.me kanali uchun qo'shimcha ogohlantirish
        tg_channel_w = []
        if tg_channel.get("found"):
            ch_title = tg_channel.get("title", "")
            if tg_channel.get("brand_in_title") and not tg_channel.get("verified"):
                for brand in tg_channel["brand_in_title"]:
                    tag = "🇺🇿" if brand in UZBEK_BRANDS else "🌐"
                    tg_channel_w.append(
                        f"🔴 {tag} Kanal `{brand}` brendini taqlid qiladi lekin TASDIQLANMAGAN!"
                    )
            if tg_channel.get("title_has_homograph"):
                tg_channel_w.append(
                    f"🔴 Kanal nomida unicode harflar — homograf hujum: `{ch_title}`"
                )
        elif tg_channel.get("deleted"):
            # Kanal o'chirilgan — fishing yuborib ketishgan
            uname = tg_channel.get("username", "")
            tg_channel_w.append(
                f"🔴 @{uname} — bot/kanal O'CHIRILGAN! Spam yuborib ketishgan — klassik fishing belgisi"
            )
        elif tg_channel.get("is_private_invite"):
            tg_channel_w.append("⚠️ Yopiq Telegram kanal taklifi — kim ekanligini ko'rib bo'lmaydi")

        # 3. DNS
        try:
            ip = await loop.run_in_executor(executor, socket.gethostbyname, domain)
        except Exception:
            ip = "Noma'lum"

        # 4. Barcha tarmoq tekshiruvlari + brauzer tekshiruvi PARALLEL
        results = await asyncio.gather(
            loop.run_in_executor(executor, _get_geo, ip),
            loop.run_in_executor(executor, check_ssl, domain),
            loop.run_in_executor(executor, check_whois, domain),
            loop.run_in_executor(executor, check_virustotal, final_url),
            loop.run_in_executor(executor, check_urlhaus, final_url),
            loop.run_in_executor(executor, check_abuseipdb, ip),
            check_with_browser(final_url),
            return_exceptions=True,
        )

        def safe(r, default):
            return r if not isinstance(r, Exception) else default

        geo        = safe(results[0], {})
        ssl_info   = safe(results[1], {"valid": False, "days_left": 0, "issuer": "Noma'lum"})
        whois_info = safe(results[2], {"age_days": None, "registrar": "Noma'lum"})
        vt         = safe(results[3], {"available": False})
        urlhaus    = safe(results[4], {"available": False})
        abuse      = safe(results[5], {"available": False})
        browser    = safe(results[6], {"available": False})

        # Brauzer redirect yangi domenni topsa — uni ham tahlil qilamiz
        if browser.get("available") and browser.get("redirected"):
            real_url = browser.get("final_url", "")
            real_parsed = urllib.parse.urlparse(real_url)
            real_domain = (real_parsed.netloc or real_parsed.path).split(":")[0]
            if real_domain and real_domain != domain:
                # Yangi domen uchun geo va risk belgilari
                brand_w += check_brand_impersonation(real_domain)
                homograph_w += check_homograph(real_domain)
                tg_url_w += check_telegram_url(real_url)

        country = geo.get("country", "Noma'lum")
        isp     = geo.get("isp", "Noma'lum")
        org     = geo.get("org", "Noma'lum")

        # Brauzer tekshiruvi natijasini risk ogohlantirishlariga qo'shamiz
        browser_w = []
        if browser.get("available"):
            if browser.get("has_card_input"):
                browser_w.append("🔴 Sahifada karta raqami kiritish shakli topildi!")
            if browser.get("has_password"):
                browser_w.append("🔴 Sahifada parol kiritish shakli topildi!")
            if browser.get("has_form") and not browser.get("has_card_input") and not browser.get("has_password"):
                browser_w.append("⚠️ Sahifada ma'lumot kiritish shakli bor")
            if browser.get("redirected"):
                browser_w.append(f"🔀 Brauzer haqiqiy manzilga o'tkazdi: `{browser.get('final_url', '')[:80]}`")

        all_tg_w = tg_url_w + tg_channel_w
        score, reasons = calculate_risk(
            domain, country, ssl_info, whois_info, redirected,
            vt, urlhaus, abuse, pattern_w, brand_w, homograph_w,
            tg_url_w=all_tg_w,
            context_w=(context_w or []) + browser_w,
        )
        label = risk_label(score)

        # ── Formatlash ──
        ssl_str = (
            f"✅ Ha ({ssl_info['days_left']} kun · {ssl_info['issuer']})"
            if ssl_info["valid"] else "❌ Yo'q"
        )

        if redirected and len(chain) > 1:
            chain_lines = "\n🔗 *Yo'naltirish zanjiri:*\n"
            for i, hop in enumerate(chain[:6]):
                prefix = "└→" if i == len(chain) - 1 else "├→"
                chain_lines += f"  {prefix} `{hop[:80]}`\n"
        else:
            chain_lines = "🔗 *Yo'naltirish:* Yo'q"

        # Telegram kanal bloki
        if tg_channel.get("found"):
            verified_str = "✅ Tasdiqlangan" if tg_channel.get("verified") else "❌ Tasdiqlanmagan"
            members = tg_channel.get("member_count")
            members_str = f"{members:,}" if members else "Noma'lum"
            tg_block = (
                f"\n📱 *Telegram kanal ma'lumoti:*\n"
                f"📛 *Nomi:* {tg_channel.get('title', '—')}\n"
                f"🔖 *Username:* @{tg_channel.get('username', '—')}\n"
                f"✅ *Tasdiqlangan:* {verified_str}\n"
                f"👥 *A'zolar:* {members_str}\n"
            )
        elif tg_channel.get("deleted"):
            uname = tg_channel.get("username", "")
            tg_block = (
                f"\n📱 *Telegram kanal ma'lumoti:*\n"
                f"🔖 *Username:* @{uname}\n"
                f"🗑 *Holat:* O'CHIRILGAN — spam yuborib o'chirib ketishgan\n"
            )
        elif tg_channel.get("is_private_invite"):
            tg_block = "\n📱 *Telegram:* Yopiq kanal taklifi — kirish mumkin emas\n"
        elif is_telegram_link:
            path = urllib.parse.urlparse(final_url).path.strip("/").split("?")[0]
            tg_block = f"\n📱 *Telegram:* `@{path}` — ma'lumot olishning imkoni yo'q\n"
        else:
            tg_block = ""

        if vt.get("available"):
            if vt.get("pending"):
                vt_str = "⏳ Yangi havola — tahlil topshirildi"
            else:
                icon = "🔴" if vt["malicious"] > 0 else "🟢"
                vt_str = f"{icon} {vt['malicious']}/{vt['total']} engine xavfli dedi"
        else:
            vt_str = "⚪ API kalit yo'q"

        if urlhaus.get("available"):
            if urlhaus.get("found"):
                tags = ", ".join(urlhaus.get("tags", [])[:3])
                uh_str = f"🔴 Bazada topildi! ({urlhaus.get('threat', 'malware')}{' · ' + tags if tags else ''})"
            else:
                uh_str = "🟢 URLhaus bazasida yo'q"
        else:
            uh_str = "⚪ Tekshirib bo'lmadi"

        if abuse.get("available"):
            s = abuse.get("abuse_score", 0)
            icon = "🔴" if s > 50 else "🟡" if s > 25 else "🟢"
            abuse_str = f"{icon} {s}/100 ({abuse.get('total_reports', 0)} shikoyat)"
        else:
            abuse_str = "⚪ API kalit yo'q"

        # Brauzer natijasi bloki
        if browser.get("available"):
            b_final = browser.get("final_url", final_url)
            b_title = browser.get("title", "—")
            b_card  = "🔴 BOR" if browser.get("has_card_input") else "🟢 Yo'q"
            b_pass  = "🔴 BOR" if browser.get("has_password") else "🟢 Yo'q"
            b_redir = f"🔀 `{b_final[:80]}`" if browser.get("redirected") else "✅ Yo'q"
            browser_block = (
                f"\n🌐 *Brauzer tekshiruvi:*\n"
                f"📄 *Sahifa nomi:* {b_title}\n"
                f"🔀 *Haqiqiy manzil:* {b_redir}\n"
                f"💳 *Karta shakli:* {b_card}\n"
                f"🔑 *Parol shakli:* {b_pass}\n"
            )
        else:
            browser_block = "\n🌐 *Brauzer:* playwright o'rnatilmagan\n"

        report = (
            f"🔍 *Havola tahlili:*\n"
            f"🌐 *Domen:* `{domain}`\n"
            f"📌 *IP:* `{ip}` · {country}\n"
            f"🏢 *Hosting:* {isp}\n"
            f"🔒 *Tashkilot:* {org}\n"
            f"🛡 *SSL:* {ssl_str}\n"
            f"📅 *Domen yoshi:* {format_age(whois_info.get('age_days'))} · "
            f"{whois_info.get('registrar', 'Noma''lum')}\n"
            f"{chain_lines}"
            f"{tg_block}"
            f"{browser_block}\n"
            f"*🔬 Threat Intelligence:*\n"
            f"🦠 *VirusTotal:* {vt_str}\n"
            f"☣️ *URLhaus:* {uh_str}\n"
            f"🚨 *AbuseIPDB:* {abuse_str}\n\n"
            f"📊 *Xavf darajasi: {score}/100 — {label}*"
        )

        if reasons:
            reasons_block = "\n\n*⚠️ Topilgan muammolar:*\n" + "\n".join(reasons[:8])
            if len(report) + len(reasons_block) < 4000:
                report += reasons_block

        return report, score

    except Exception:
        return f"🌐 *Havola:* `{url}`\n❌ Tahlil qilib bo'lmadi.", 0


# ── Komanda handlerlari ─────────────────────────────────────────────────────

@dp.message(Command("start", "help"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🛡 *Fishing Aniqlagich Bot*\n\n"
        "Telegram xabarlaridagi havolalarni professional darajada tahlil qiladi.\n\n"
        "*Bot nima tekshiradi?*\n"
        "🦠 VirusTotal — 70+ antivirus bazasi\n"
        "☣️ URLhaus — malware/phishing URL bazasi (abuse.ch)\n"
        "🚨 AbuseIPDB — spam/hujum IP bazasi\n"
        "🛡 SSL sertifikat holati va muddati\n"
        "📅 Domen yoshi (WHOIS)\n"
        "🔗 Yo'naltirish zanjiri (har bir qadam)\n"
        "🔤 Homograf hujum aniqlash\n"
        "🇺🇿 O'zbek brendlari taqlidi aniqlash\n"
        "📊 0–100 ballik xavf tizimi\n\n"
        "*Foydalanish:*\n"
        "Shubhali xabarni menga *forward* qiling yoki havola yuboring.\n\n"
        "*Buyruqlar:*\n"
        "/stats — Statistika",
        parse_mode="Markdown",
    )

@dp.message(Command("stats"))
async def cmd_stats(message: types.Message):
    total, dangerous = get_stats()
    await message.answer(
        f"📊 *Bot statistikasi:*\n\n"
        f"🔍 Jami tekshirilgan: *{total}* ta\n"
        f"🔴 Xavfli (≥50 ball): *{dangerous}* ta\n"
        f"🟢 Xavfsiz (<50 ball): *{total - dangerous}* ta",
        parse_mode="Markdown",
    )


# ── Asosiy xabar handleri ───────────────────────────────────────────────────

@dp.message()
async def handle_message(message: types.Message):
    urls_to_check: set[str] = set()

    text = message.text or message.caption or ""

    for entity in (message.entities or message.caption_entities or []):
        if entity.type == "url":
            url = text[entity.offset : entity.offset + entity.length]
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            urls_to_check.add(url)
        elif entity.type == "text_link" and entity.url:
            urls_to_check.add(entity.url)

    if message.reply_markup and hasattr(message.reply_markup, "inline_keyboard"):
        for row in message.reply_markup.inline_keyboard:
            for btn in row:
                if btn.url:
                    urls_to_check.add(btn.url)
                # WebApp tugmasi — fishing saytlar shu yerda yashirinadi
                if btn.web_app and btn.web_app.url:
                    urls_to_check.add(btn.web_app.url)

    # Xabar kontekstini tahlil qilamiz (forward, tugma matni)
    context_w = check_message_context(message)

    # Havolalar yo'q bo'lsa ham kontekst xavfli bo'lishi mumkin
    if not urls_to_check:
        if context_w:
            ctx_text = (
                "🚨 *Kiberxavfsizlik ogohlantirishlari:*\n\n"
                "🔗 Xabarda havola topilmadi, lekin shubhali belgilar aniqlandi:\n\n"
                + "\n".join(context_w)
                + "\n\n⚠️ _Bu xabarga ishonmang va ulashma!_"
            )
            await message.reply(ctx_text, parse_mode="Markdown")
        else:
            await message.reply("⚠️ Ushbu xabarda hech qanday havola yoki yashirin tugma topilmadi.")
        return

    await message.reply(
        f"⏳ *{len(urls_to_check)} ta havola tahlil qilinmoqda...*\n"
        f"_(VirusTotal, URLhaus, AbuseIPDB, SSL, WHOIS parallel tekshirilmoqda)_",
        parse_mode="Markdown",
    )

    for url in urls_to_check:
        result, score = await analyze_url(url, context_w=context_w)
        if result:
            save_stat(url, score)
            text_out = (
                "🚨 *Kiberxavfsizlik tahlil hisoboti:*\n\n"
                + result
                + "\n\n" + "—" * 22 + "\n"
                "⚠️ _Xavf darajasi 50+ bo'lsa karta yoki parol kiritmang!_"
            )
            try:
                await message.reply(text_out, parse_mode="Markdown")
            except Exception:
                await message.reply(text_out)


if __name__ == "__main__":
    init_db()
    print("Bot ishga tushdi...")
    dp.run_polling(bot)
