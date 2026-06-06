#!/bin/bash
echo "===================================="
echo " Fishing Bot ishga tushmoqda..."
echo "===================================="
echo

if ! command -v python3 &>/dev/null; then
    echo "[XATO] Python3 topilmadi!"
    echo "Avval install.sh ni ishga tushiring."
    exit 1
fi

if [ ! -f .env ]; then
    echo "[XATO] .env fayl topilmadi!"
    echo "Avval install.sh ni ishga tushiring."
    exit 1
fi

if grep -q "YOUR_TELEGRAM_BOT_TOKEN_HERE" .env; then
    echo "[XATO] .env fayliga hali token kiritilmagan!"
    echo "BOT_TOKEN= ga tokeningizni yozing."
    exit 1
fi

echo "[OK] Barcha tekshiruvlar o'tdi."
echo
echo "Bot ishlayapti... To'xtatish uchun Ctrl+C bosing."
echo
python3 main.py
