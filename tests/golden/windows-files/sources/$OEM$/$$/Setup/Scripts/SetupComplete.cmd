@echo off
rem EPMA USB CREATOR - optional hardened setup. Checks harden.ps1, runs it once, logs, never fails the setup.
set "EPMA_LOG=%windir%\Temp\epma-hardening.log"
set "EPMA_WANT=854d5bb5a0de4407c6a5f4f3b15b0f0f432291b9e28e271bee7e7598fb9a7411"
set "EPMA_GOT="
echo [%date% %time%] SetupComplete.cmd: starting >> "%EPMA_LOG%"
if not exist "%~dp0harden.ps1" goto missing
for /f "skip=1 delims=" %%H in ('%SystemRoot%\System32\certutil.exe -hashfile "%~dp0harden.ps1" SHA256 2^>nul') do if not defined EPMA_GOT set "EPMA_GOT=%%H"
if not defined EPMA_GOT goto nohash
set "EPMA_GOT=%EPMA_GOT: =%"
if /i not "%EPMA_GOT%"=="%EPMA_WANT%" goto mismatch
echo [%date% %time%] SetupComplete.cmd: harden.ps1 SHA-256 matches >> "%EPMA_LOG%"
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1" >> "%EPMA_LOG%" 2>&1
echo [%date% %time%] SetupComplete.cmd: harden.ps1 exit code %errorlevel% (ignored) >> "%EPMA_LOG%"
goto done
:missing
echo [SKIP] harden.ps1 not found next to SetupComplete.cmd >> "%EPMA_LOG%"
goto done
:nohash
echo [SKIP] could not compute the SHA-256 of harden.ps1 (certutil failed): harden.ps1 was NOT run >> "%EPMA_LOG%"
goto done
:mismatch
echo [SKIP] harden.ps1 does not match the SHA-256 recorded in SetupComplete.cmd: harden.ps1 was NOT run >> "%EPMA_LOG%"
echo [SKIP] expected %EPMA_WANT% but found %EPMA_GOT% >> "%EPMA_LOG%"
:done
exit /b 0
