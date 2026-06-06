@echo off
title Fishing Bot
echo ====================================
echo  Fishing Bot ishga tushmoqda...
echo ====================================
echo.

:: Python borligini tekshiramiz
python --version >nul 2>&1
if errorlevel 1 (
    echo [XATO] Python topilmadi!
    echo Avval install.bat ni ishga tushiring.
    pause
    exit /b 1
)

:: .env fayl borligini tekshiramiz
if not exist .env (
    echo [XATO] .env fayl topilmadi!
    echo Avval install.bat ni ishga tushiring.
    pause
    exit /b 1
)

:: Token kiritilganligini tekshiramiz
findstr /c:"YOUR_TELEGRAM_BOT_TOKEN_HERE" .env >nul 2>&1
if not errorlevel 1 (
    echo [XATO] .env fayliga hali token kiritilmagan!
    echo BOT_TOKEN= ga tokeningizni yozing va saqlang.
    notepad .env
    pause
    exit /b 1
)

echo [OK] Barcha tekshiruvlar o'tdi.
echo.
echo Bot ishlayapti... To'xtatish uchun Ctrl+C bosing.
echo.
python main.py

echo.
echo Bot to'xtatildi.
pause
