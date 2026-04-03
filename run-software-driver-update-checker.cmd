@echo off
setlocal

REM Wrapper to run software-driver-update-checker.ps1 even when script-signing policy blocks direct invocation.
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%software-driver-update-checker.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"

endlocal & exit /b %EXIT_CODE%
