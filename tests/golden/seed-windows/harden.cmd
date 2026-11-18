@echo off
setlocal
set "NoDefaultCurrentDirectoryInExePath=1"
rem harden.cmd: EPMA hardening seed for Windows 11 (EXPERIMENTAL scripts, see README.txt).
rem Runs harden.ps1 -Mode Apply from this folder. Nothing is installed or downloaded.
title EPMA hardening - Apply
set "EPMA_SELF=%~f0"
echo.
echo EPMA USB CREATOR - hardening of this Windows PC. EXPERIMENTAL scripts.
echo This applies a small set of recommended security settings with harden.ps1.
echo Nothing is installed and nothing is downloaded. A log is written to
echo C:\Windows\Temp\epma-hardening.log. Run audit.cmd first to see a report.
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
%SystemRoot%\System32\choice.exe /c yn /n /m "Continue? [y/N] "
if errorlevel 2 goto :cancel
if errorlevel 1 goto :run
:cancel
echo.
echo Cancelled. Nothing was changed.
pause
exit /b 1

:run
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1" -Mode Apply
set "RC=%errorlevel%"
echo.
echo Finished with exit code %RC%. Read the lines above: a [WARN] line means a
echo setting is not in effect. A restart may be needed for a few settings.
pause
exit /b %RC%
