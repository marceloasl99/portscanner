@echo off
rem Double-click launcher for local-scanner.ps1 (runs only on this computer, no network request).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0local-scanner.ps1"
