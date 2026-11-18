EPMA HARDENING SEED - Windows 11 (experimental scripts)
============================================================

WHAT THIS DRIVE IS
A small helper drive made by EPMA USB CREATOR. It holds a PowerShell script
and three double-click launchers that apply a small set of recommended
security settings to Windows 11. It is a SECOND small USB. It is NOT a
Windows installer and it does not boot by itself. Nothing is installed and
nothing is downloaded.

HOW TO USE IT: RUN IT AFTER WINDOWS IS INSTALLED
1. Install Windows 11 as usual, then sign in with an administrator account.
2. Plug this drive in and open it in File Explorer.
3. Right-click audit.cmd and choose Open (or double-click it) FIRST. Windows
   asks for permission (the User Account Control prompt): choose Yes.
   audit.cmd does not ask you to confirm anything: it only shows a report of
   what is in effect and changes nothing. In the report [OK] means in
   effect, [DIFF] means NOT in effect and [N/A] means it does not apply to
   this PC.
4. Then double-click harden.cmd. Windows asks for permission again: choose
   Yes. harden.cmd then asks 'Continue? [y/N]': press y to apply the
   settings, n to cancel.
5. Read the lines it prints. A [WARN] line means that a setting is NOT in
   effect. Nothing was forced.
6. To go back, double-click undo.cmd (it asks 'Continue? [y/N]' too). Read
   the limits of undo.cmd below.

harden.cmd and undo.cmd write a log to C:\Windows\Temp\epma-hardening.log.
audit.cmd only prints in its window. A restart may be needed for a few
settings. Running harden.cmd twice changes nothing more.

LIMITS OF UNDO.CMD
  - undo.cmd puts back the settings that harden.ps1 recorded when it changed
    them.
  - It does not turn SMBv1 or PowerShell 2.0 on again (the log prints the
    command to do it by hand), and it does not lower the Security log size.
  - A setting that was already in the wanted state before harden.cmd ran is
    not recorded, so undo.cmd leaves it as it is.
  - undo.cmd can finish with a non-zero exit code when one of its steps
    failed: read the lines it prints.

WHAT THE SCRIPT CHANGES
  - Turn off SMBv1 (obsolete file-sharing protocol)
  - Turn off LLMNR name lookups
  - Turn off AutoRun and AutoPlay on every drive type
  - Windows Firewall on for all network profiles, inbound blocked unless a
    rule allows it
  - Defender: block potentially unwanted apps and turn cloud protection on
  - Defender attack surface rule in Block mode: no credential stealing from
    LSASS
  - Defender attack surface rules in Audit mode (log only): email executable
    content, Office child processes, obfuscated scripts, script-launched
    downloads
  - Defender attack surface rules in Audit mode (log only), more: abuse of
    exploited vulnerable signed drivers, process creation from PsExec and
    WMI commands, untrusted processes that run from USB drives
  - Do not keep plain-text WDigest credentials in memory
  - PowerShell script block logging
  - Disable the PowerShell 2.0 optional feature
  - Turn off Remote Assistance invitations
  - Advanced audit policy: sign-ins, account lockouts, account and group
    changes, audit-policy changes, process creation; Security log size
    raised to 128 MiB
  - Keep User Account Control switched on
  - Opt-in, never applied by default: harden.ps1 can also turn off NetBIOS
    over TCP/IP and WPAD proxy auto-discovery (it can break very old
    networks). To apply them too, open PowerShell as administrator, go to
    this drive (for example: E:) and run this command (type it as one line):
      powershell -ExecutionPolicy Bypass -File harden.ps1 -Mode Apply
        -DisableLegacyNetwork

WHAT IT LEAVES ALONE
  - BitLocker is not turned on automatically. It needs a TPM, a choice of
    where the recovery key goes and the owner's consent; a wrong default can
    lock someone out of their own data.
  - NTLM authentication levels are left as they are. Stricter levels can
    break access to older file shares, printers and NAS devices without any
    warning.
  - Accounts, passwords, disks, language, licence and product key. Windows
    Setup stays fully interactive; the hardening script never touches them.
  - Memory Integrity (HVCI), Credential Guard and Exploit Protection are
    only reported, never turned on. They depend on the hardware, drivers and
    apps of each PC and can stop a PC from starting or a program from
    running; Audit mode shows their state so the owner can decide.

READ THE FILES BEFORE YOU RUN THEM
harden.cmd, audit.cmd, undo.cmd and harden.ps1 are plain text files. Open
them in Notepad (right-click, Open with) and read them first. Each launcher
asks for administrator rights and runs harden.ps1 from this drive.
harden.cmd and undo.cmd also ask you to confirm; audit.cmd does not.

HONEST CAVEATS
  - These settings are inspired by common security baselines. They are a
    sensible starting point, not a compliance claim, certification or
    guarantee.
  - The PowerShell script was never executed by its authors on a real
    Windows PC. Try it on a spare PC or in a virtual machine before you use
    it on a PC you depend on.
  - Another antivirus program or Windows Tamper Protection can stop the
    Windows Defender settings from being changed. The script then prints a
    [WARN] line.
  - Nothing here selects a disk, partitions or erases anything, and nothing
    creates an account or sets a password.
  - This drive is not protected or authenticated in any way: whatever is on
    it runs with administrator rights when you use a launcher. Keep it with
    you.
