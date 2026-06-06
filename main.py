import os
import socket
import urllib.parse
import requests
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types, F

# .env faylidan tokenni yuklaymiz
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Fishing havolasini tahlil qiluvchi funksiya
def analyze_url(url: str) -> str:
    try:
        # Havoladan faqat domen nomini ajratib olamiz
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        if not domain:
            return None

        # Domenni IP manzilga o'giramiz
        ip_address = socket.gethostbyname(domain)

        # IP-API orqali server va provayder ma'lumotlarini olamiz
        geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5).json()

        country = geo_response.get("country", "Noma'lum")
        isp = geo_response.get("isp", "Noma'lum")  # Provayder / Hosting
        org = geo_response.get("org", "Noma'lum")  # Tashkilot

        report = (
            f"🔍 **Topilgan havola tahlili:**\n"
            f"🌐 **Domen:** `{domain}`\n"
            f"📌 **IP Manzil:** `{ip_address}`\n"
            f"🌍 **Server joylashgan joy:** {country}\n"
            f"🏢 **Hosting Provayder:** {isp}\n"
            f"🔒 **Tashkilot:** {org}\n"
        )
        return report
    except Exception:
        return f"🌐 **Domen:** `{url}`\n❌ *Ushbu domen haqida ma'lumot olib bo'lmadi yoki u bloklangan.*"


# Botga har qanday xabar (matn, rasm yoki tugmali xabar) kelganda ushlab qoluvchi handler
@dp.message()
async def handle_incoming_message(message: types.Message):
    urls_to_check = set()

    # 1. Matn ichidagi oddiy havolalarni qidiramiz
    if message.text:
        text = message.text
    elif message.caption:  # Agar rasm ostidagi matn bo'lsa
        text = message.caption
    else:
        text = ""

    # Telegram o'zi aniqlagan havolalarni (entities) tekshiramiz
    entities = message.entities or message.caption_entities
    if entities:
        for entity in entities:
            if entity.type == "url":
                # Matndan linkni kesib olamiz
                url = text[entity.offset:entity.offset + entity.length]
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                urls_to_check.add(url)
            elif entity.type == "text_link":
                # Yashirin matnli havolalar (masalan: [mana bu yerga bosing](link))
                urls_to_check.add(entity.url)

    # 2. Xabarning pastidagi yashil tugmalarni (Inline Keyboards) tekshiramiz
    if message.reply_markup and message.reply_markup.inline_keyboard:
        for row in message.reply_markup.inline_keyboard:
            for button in row:
                if button.url:  # Agar tugmaga link biriktirilgan bo'lsa
                    urls_to_check.add(button.url)

    # 3. Natijalarni tahlil qilib javob qaytaramiz
    if not urls_to_check:
        await message.reply("⚠️ Ushbu xabarda hech qanday havola (link) yoki yashirin tugma topilmadi.")
        return

    await message.reply("⏳ Xabar ichidagi havolalar tahlil qilinmoqda...")

    final_response = "🚨 **Kiberxavfsizlik tahlil hisoboti:**\n\n"
    for url in urls_to_check:
        analysis_result = analyze_url(url)
        if analysis_result:
            final_response += analysis_result + "\n" + "—" * 20 + "\n"

    final_response += "\n⚠️ **Eslatma:** Agar server xorijda (masalan, Rossiya, AQSh, Yevropa) joylashgan bo'lsa va u rasmiy tashkilotga tegishli bo'lmasa, u yerga plastik karta ma'lumotlarini MUTLAQO kiritmang!"

    await message.reply(final_response, parse_mode="Markdown")


# Botni ishga tushirish
if __name__ == "__main__":
    print("Bot ishga tushdi...")
    dp.run_polling(bot)
