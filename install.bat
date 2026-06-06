@echo off
title Kutubxonalarni o'rnatish...
echo ====================================
echo  Fishing Bot - O'rnatish
echo ====================================
echo.

:: Python borligini tekshiramiz
python --version >nul 2>&1
if errorlevel 1 (
    echo [XATO] Python topilmadi!
    echo Python.org dan yuklab o'rnating: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python topildi:
python --version
echo.

:: .env fayl borligini tekshiramiz
if not exist .env (
    copy .env.example .env >nul
    echo [!] .env fayl yaratildi.
    echo.
    echo ============================================================
    echo  Muhim: .env faylini oching va quyidagilarni to'ldiring:
    echo.
    echo  BOT_TOKEN      - @BotFather dan oling (majburiy)
    echo  VIRUSTOTAL_API_KEY - virustotal.com dan bepul (tavsiya)
    echo  ABUSEIPDB_API_KEY  - abuseipdb.com dan bepul (tavsiya)
    echo ============================================================
    echo.
    notepad .env
) else (
    echo [OK] .env fayl mavjud.
)

echo.
echo [*] Kutubxonalar o'rnatilmoqda...
echo.
pip install -r requirements.txt

echo.
if errorlevel 1 (
    echo [XATO] O'rnatishda xatolik yuz berdi!
) else (
    echo ====================================
    echo  O'rnatish muvaffaqiyatli tugadi!
    echo  Endi start.bat ni ishga tushiring.
    echo ====================================
)
echo.
pause
