@echo off
title DeepInsight Dashboard Launcher
color 0B

echo ========================================================
echo          DEEPINSIGHT PACKET ANALYZER LAUNCHER
echo ========================================================
echo.

:: Check Node.js availability
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in your PATH!
    echo Please install Node.js from https://nodejs.org/ before launching.
    echo.
    pause
    exit /b 1
)

:: Install dependencies if node_modules folder is missing
if not exist "node_modules\" (
    echo [INFO] node_modules not found. Installing dependencies...
    call npm install
    if %errorlevel% neq 0 (
        echo [ERROR] npm install failed. Check your internet connection.
        pause
        exit /b 1
    )
)

:: Auto launch default browser
echo [INFO] Launching Web Interface...
start http://localhost:3000

:: Run backend server
echo [INFO] Starting Express API Server...
node server.js

pause
