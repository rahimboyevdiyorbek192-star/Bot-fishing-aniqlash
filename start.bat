@echo off
title Fishing Bot - Ishlamoqda
echo ====================================
echo  Fishing Bot ishga tushmoqda...
echo ====================================
echo.

:: Python tekshiruvi
python --version >nul 2>&1
if errorlevel 1 (
    echo [XATO] Python topilmadi!
    echo Avval install.bat ni ishga tushiring.
    pause
    exit /b 1
)

:: .env tekshiruvi
if not exist .env (
    echo [XATO] .env fayl topilmadi!
    echo Avval install.bat ni ishga tushiring.
    pause
    exit /b 1
)

:: Token kiritilganligini tekshiramiz
findstr /c:"YOUR_TELEGRAM_BOT_TOKEN_HERE" .env >nul 2>&1
if not errorlevel 1 (
    echo [XATO] BOT_TOKEN hali kiritilmagan!
    echo .env faylni oching va tokeningizni yozing.
    notepad .env
    pause
    exit /b 1
)

echo [OK] Sozlamalar topildi.
echo.
echo ============================================================
echo  Bot ishlayapti!
echo  To'xtatish uchun: Ctrl + C
echo ============================================================
echo.
python main.py

echo.
echo Bot to'xtatildi.
pause
