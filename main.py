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
        # t.me/+xxx — yopiq kanal invite havolasi, shubhali
        if path.startswith("+"):
            warnings.append("⚠️ Yopiq Telegram kanal taklifi — ehtiyot bo'ling")
        return warnings
    for brand in ALL_BRANDS:
        brand_clean = brand.replace("_", "").replace("-", "")
        if brand_clean in path:
            tag = "🇺🇿" if brand in UZBEK_BRANDS else "🌐"
            warnings.append(
                f"⚠️ {tag} Telegram havola `{brand}` brendini taqlid qilishi mumkin: `t.me/{parsed.path.strip('/')}`"
            )
    return warnings

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

    # Inline tugma matni tekshiruvi
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

    # Telegram havola ichida brend taqlid
    if tg_url_w:
        score += 30
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

        # 3. DNS
        try:
            ip = await loop.run_in_executor(executor, socket.gethostbyname, domain)
        except Exception:
            ip = "Noma'lum"

        # 4. Barcha tarmoq tekshiruvlari PARALLEL
        results = await asyncio.gather(
            loop.run_in_executor(executor, _get_geo, ip),
            loop.run_in_executor(executor, check_ssl, domain),
            loop.run_in_executor(executor, check_whois, domain),
            loop.run_in_executor(executor, check_virustotal, final_url),
            loop.run_in_executor(executor, check_urlhaus, final_url),
            loop.run_in_executor(executor, check_abuseipdb, ip),
            return_exceptions=True,
        )

        def safe(r, default):
            return r if not isinstance(r, Exception) else default

        geo        = safe(results[0], {})
        ssl_info   = safe(results[1], {"valid": False, "days_left": 0, "issuer": "Noma'lum"})
        whois_info = safe(results[2], {"age_days": None, "registrar": "Noma'lum"})
        vt      = safe(results[3], {"available": False})
        urlhaus = safe(results[4], {"available": False})
        abuse   = safe(results[5], {"available": False})

        country = geo.get("country", "Noma'lum")
        isp     = geo.get("isp", "Noma'lum")
        org     = geo.get("org", "Noma'lum")

        score, reasons = calculate_risk(
            domain, country, ssl_info, whois_info, redirected,
            vt, urlhaus, abuse, pattern_w, brand_w, homograph_w,
            tg_url_w=tg_url_w,
            context_w=context_w or [],
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

        report = (
            f"🔍 *Havola tahlili:*\n"
            f"🌐 *Domen:* `{domain}`\n"
            f"📌 *IP:* `{ip}` · {country}\n"
            f"🏢 *Hosting:* {isp}\n"
            f"🔒 *Tashkilot:* {org}\n"
            f"🛡 *SSL:* {ssl_str}\n"
            f"📅 *Domen yoshi:* {format_age(whois_info.get('age_days'))} · {whois_info.get('registrar', 'Noma''lum')}\n"
            f"{chain_lines}\n\n"
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
