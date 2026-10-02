@echo off
cd /d "%~dp0"
py -3 server.py --cors on
pause
