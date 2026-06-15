# Bot-fishing-aniqlash

Telegram guruh/kanal a'zolarini yig'uvchi OSINT skaner (Telethon).

## Asosiy xususiyat: o'chirilgan hisoblarni oldindan ilg'ash

O'chirilgan akkauntlar (**Deleted Account**) `user.deleted` belgisi orqali,
**qo'shimcha API so'rovisiz** aniqlanadi. Bunday hisoblar uchun bio so'rovi
(`GetFullUser`) **yuborilmaydi** — natijada keraksiz API so'rovlari tejaladi
va flood-wait xavfi kamayadi.

> Eslatma: "Deleted Account" degan **matn** ism emas — u kod qo'yadigan yorliq.
> Aniqlash faqat rasmiy `deleted` belgisiga tayanadi (matn solishtiruviga emas).

## O'rnatish

```bash
pip install -r requirements.txt
cp .env.example .env     # API_ID, API_HASH ni to'ldiring (my.telegram.org)
```

## Ishlatish

```bash
python scanner.py -e https://t.me/Durmon1643
python scanner.py -e @guruh1 -e @guruh2     # bir nechta manba
```

Natija `OSINT_Monitoring.xlsx` fayliga yoziladi (ustunlar mavjud formatga mos).
