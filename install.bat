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

echo [OK] Python topildi.
echo.

:: .env fayl borligini tekshiramiz
if not exist .env (
    copy .env.example .env >nul
    echo [!] .env fayl yaratildi.
    echo [!] Iltimos .env faylni oching va BOT_TOKEN ga o'z tokeningizni yozing.
    echo.
    notepad .env
) else (
    echo [OK] .env fayl mavjud.
)

echo.
echo [*] Kutubxonalar o'rnatilmoqda...
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
