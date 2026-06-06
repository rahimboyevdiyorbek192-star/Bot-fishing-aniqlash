#!/bin/bash
echo "===================================="
echo " Fishing Bot - O'rnatish"
echo "===================================="
echo

# Python tekshiruvi
if ! command -v python3 &>/dev/null; then
    echo "[XATO] Python3 topilmadi!"
    echo "sudo apt install python3 python3-pip"
    exit 1
fi

echo "[OK] Python topildi: $(python3 --version)"
echo

# .env fayl
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[!] .env fayl yaratildi."
    echo "[!] .env faylni oching va BOT_TOKEN ga tokeningizni yozing."
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
    echo " Endi:  bash start.sh"
    echo "===================================="
else
    echo "[XATO] O'rnatishda xatolik yuz berdi!"
fi
