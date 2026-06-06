#!/bin/bash
echo "===================================="
echo " Fishing Bot - O'rnatish"
echo "===================================="
echo

if ! command -v python3 &>/dev/null; then
    echo "[XATO] Python3 topilmadi!"
    echo "sudo apt install python3 python3-pip"
    exit 1
fi
echo "[OK] $(python3 --version)"
echo

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[!] .env fayl yaratildi."
    echo
    echo "============================================================"
    echo " Muhim: .env faylini oching va quyidagilarni to'ldiring:"
    echo
    echo "  BOT_TOKEN           - @BotFather dan oling (majburiy)"
    echo "  VIRUSTOTAL_API_KEY  - virustotal.com dan bepul (tavsiya)"
    echo "  ABUSEIPDB_API_KEY   - abuseipdb.com dan bepul (tavsiya)"
    echo "============================================================"
    echo
    read -p "Davom etish uchun Enter bosing..."
else
    echo "[OK] .env fayl mavjud."
fi

echo
echo "[*] Kutubxonalar o'rnatilmoqda..."
pip3 install -r requirements.txt

echo
if [ $? -eq 0 ]; then
    echo "===================================="
    echo " O'rnatish muvaffaqiyatli tugadi!"
    echo " Endi: bash start.sh"
    echo "===================================="
else
    echo "[XATO] O'rnatishda xatolik yuz berdi!"
fi
