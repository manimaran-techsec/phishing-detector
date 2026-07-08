@echo off
title AI Phishing Detection System
color 0A
echo.
echo ================================================
echo   AI Phishing Detection System - Starting...
echo ================================================
echo.
cd /d C:\Users\ADMIN\PhishingDetector
echo [1/2] Starting server...
start http://localhost:5000
venv\Scripts\python.exe demo_run.py
pause
