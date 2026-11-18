# EPMA USB CREATOR - optional hardened setup for Windows 11 (recommended settings inspired by common
# baselines; this is NOT a compliance profile). One script, three situations:
#   * Windows Setup: SetupComplete.cmd runs it once as SYSTEM with no arguments (mode Apply, today's behaviour).
#   * An installed Windows 11: an administrator runs it (harden.cmd does), in any of the three modes.
# Parameters:
#   -Mode Apply   (default) applies the settings below. Before a setting is changed, its previous value is
#                 recorded in @STATE@ (a value already recorded is
#                 never overwritten). Safe to run again: it changes nothing that is already set.
#   -Mode Audit   changes NOTHING in the configuration and writes no state file: prints [OK] in effect / [DIFF]
#                 not in effect / [N/A] per setting, then read-only facts (BitLocker, TPM, Secure Boot, Defender,
#                 attack surface rules, Memory Integrity, Credential Guard, Exploit Protection), then a [DONE] line.
#                 The one thing it can write is not a configuration change: the DISM cmdlets that read the optional
#                 features may write their own logs under C:\Windows\Logs\DISM (an [INFO] line says so).
#   -Mode Undo    puts back every recorded value (or removes a value that did not exist). It cannot turn
#                 optional features on again (it prints the Enable-WindowsOptionalFeature command), it does not
#                 shrink the Security log, never writes the SMBv1 server value back as 1, and a setting that Apply
#                 found already set was never recorded. It uses the state file for VALUES only: what is put back
#                 comes from tables built into this script, and every value is checked. A record it cannot put back
#                 is kept (run Undo again) and Undo then exits with code 1.
#   -DisableLegacyNetwork  opt-in: also turns off NetBIOS over TCP/IP and WPAD auto-discovery. Never applied
#                 without it, and never from SetupComplete.cmd.
#   -LogPath      log file (default @LOG@). Every line is also shown on the console.
# PowerShell 5.1; no network access, no downloads, no extra tools (auditpol.exe and wevtutil.exe are part of
# Windows). Every setting has its own error handler and writes one line per mode. Apply and Undo use [OK],
# [SKIP], [WARN] or [FAIL]. It must be run as administrator (it refuses otherwise). The exit code is 0 in
# Windows Setup and for Apply and Audit; run by hand it is 1 when it refuses to start (not an administrator,
# unreadable state, a state folder that cannot be trusted) and, for Undo, when any [WARN] or [FAIL] was logged.
#
# The state folder @STATE_FOLDER@ is created in one step with an access list
# for SYSTEM and Administrators only. A folder that already exists is used only if it is not a junction or
# symbolic link, is owned by SYSTEM or Administrators and nobody else can write to it; otherwise the script
# refuses and Apply changes nothing, because a setting that cannot be recorded cannot be undone.
#
# NOTHING in this file has been run on a real Windows: it was checked by structure tests only. Try Audit mode
# first, on a test PC.
#
# The script runs ONCE, at the end of Windows Setup, and does NOT retry. Firewall, Defender and the attack
# surface rules are read back after they are set: [OK] means the value is in effect; [WARN] means the command
# did not fail but the value is not in effect (Tamper Protection, another antivirus, Defender or the firewall
# service not ready yet). Run this file again as administrator to try those settings once more.
#
# Settings, each with the risk it carries:
@SETTINGS_COMMENTS@
#
# Deliberately NOT changed:
@NOT_CHANGED_COMMENTS@
