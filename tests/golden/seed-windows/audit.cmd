@echo off
setlocal
set "NoDefaultCurrentDirectoryInExePath=1"
rem audit.cmd: EPMA hardening seed for Windows 11 (EXPERIMENTAL scripts, see README.txt).
rem Runs harden.ps1 -Mode Audit from this folder. Nothing is installed or downloaded.
title EPMA hardening - Audit
set "EPMA_SELF=%~f0"
echo.
echo EPMA USB CREATOR - report on this Windows PC. EXPERIMENTAL scripts.
echo This only reports which settings are in effect. It changes nothing.
echo Nothing is installed and nothing is downloaded. Administrator rights are
echo still needed because some of the checks cannot be read without them.
echo.
%SystemRoot%\System32\net.exe session >nul 2>&1
if not errorlevel 1 goto :admin
%SystemRoot%\System32\fltmc.exe >nul 2>&1
if not errorlevel 1 goto :admin
if /i "%~1"=="elevated" goto :noadmin
echo Administrator rights are needed. Windows will now show a prompt:
echo choose Yes to continue. A new window opens for the work.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:EPMA_SELF -ArgumentList 'elevated' -Verb RunAs"
if errorlevel 1 goto :noadmin
exit /b 0

:noadmin
echo.
echo Administrator rights were not granted. Nothing was changed.
pause
exit /b 1

:admin
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1" -Mode Audit
set "RC=%errorlevel%"
echo.
echo Finished with exit code %RC%. Read the lines above: a [DIFF] line means a
echo setting is not in effect. A restart may be needed for a few settings.
pause
exit /b %RC%
