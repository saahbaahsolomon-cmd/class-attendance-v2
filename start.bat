@echo off
cd /d "%~dp0"
taskkill /f /im node.exe >nul 2>&1
if not exist node_modules call npm install
set ADMIN_KEY=mySecret
echo.
echo Starting attendance... keep this window open.
echo Open http://localhost:3000/lecturer.html in your browser.
echo Sign in:  username = admin   password = mySecret
echo.
node server.js
pause
