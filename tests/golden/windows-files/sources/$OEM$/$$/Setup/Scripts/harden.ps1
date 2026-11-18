# EPMA USB CREATOR - optional hardened setup for Windows 11 (recommended settings inspired by common
# baselines; this is NOT a compliance profile). One script, three situations:
#   * Windows Setup: SetupComplete.cmd runs it once as SYSTEM with no arguments (mode Apply, today's behaviour).
#   * An installed Windows 11: an administrator runs it (harden.cmd does), in any of the three modes.
# Parameters:
#   -Mode Apply   (default) applies the settings below. Before a setting is changed, its previous value is
#                 recorded in %ProgramData%\EPMA\hardening-state.json (a value already recorded is
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
#   -LogPath      log file (default %windir%\Temp\epma-hardening.log). Every line is also shown on the console.
# PowerShell 5.1; no network access, no downloads, no extra tools (auditpol.exe and wevtutil.exe are part of
# Windows). Every setting has its own error handler and writes one line per mode. Apply and Undo use [OK],
# [SKIP], [WARN] or [FAIL]. It must be run as administrator (it refuses otherwise). The exit code is 0 in
# Windows Setup and for Apply and Audit; run by hand it is 1 when it refuses to start (not an administrator,
# unreadable state, a state folder that cannot be trusted) and, for Undo, when any [WARN] or [FAIL] was logged.
#
# The state folder %ProgramData%\EPMA is created in one step with an access list
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
#   smb1: Turn off SMBv1 (obsolete file-sharing protocol)
#       risk/why: Very old NAS boxes, scanners or Windows XP-era PCs that only speak SMBv1 can no longer connect.
#   llmnr: Turn off LLMNR name lookups
#       risk/why: Single-word names that only resolve through LLMNR stop resolving on networks without proper DNS.
#   autorun: Turn off AutoRun and AutoPlay on every drive type
#       risk/why: Inserted USB sticks and discs no longer start installers or show the AutoPlay prompt, and phones and cameras no longer show the import-photos prompt; open them from File Explorer.
#   firewall: Windows Firewall on for all network profiles, inbound blocked unless a rule allows it
#       risk/why: A program that must accept incoming connections (game server, file sharing, remote tools) needs an allow rule. The script runs once at the end of Setup and does not retry; the log says [WARN] if the firewall settings are not in effect.
#   defender_cloud: Defender: block potentially unwanted apps and turn cloud protection on
#       risk/why: Some bundled freeware may be flagged, and cloud protection sends file metadata to Microsoft. The script runs once at the end of Setup and does not retry; Tamper Protection, another antivirus or a Defender that is not ready yet can stop the change, and the log then says [WARN].
#   asr_lsass: Defender attack surface rule in Block mode: no credential stealing from LSASS
#       risk/why: Rarely, security or backup tools that read LSASS memory are blocked and Defender shows a notification. The script runs once at the end of Setup and does not retry; the log says [WARN] if the rule is not in effect.
#   asr_audit: Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads
#       risk/why: Audit mode only writes events and blocks nothing. Review the Defender event log before switching any rule to Block. The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect.
#   asr_audit_extra: Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives
#       risk/why: Audit mode only writes events and blocks nothing; running programs from a USB stick or with remote-management tools adds events. Review the Defender event log before switching any rule to Block. The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect.
#   wdigest: Do not keep plain-text WDigest credentials in memory
#       risk/why: Only legacy digest authentication against very old web servers is affected.
#   ps_logging: PowerShell script block logging
#       risk/why: Adds events to the PowerShell log; secrets typed inside a script would be logged as well.
#   ps2: Disable the PowerShell 2.0 optional feature
#       risk/why: Very old scripts or tools that insist on running with -Version 2 stop working.
#   remote_assist: Turn off Remote Assistance invitations
#       risk/why: Old-style Remote Assistance invitations stop working; Quick Assist and Remote Desktop are not changed.
#   audit: Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB
#       risk/why: The Security event log fills much faster (process creation and sign-ins are frequent events), so its maximum size is raised to 128 MiB (never lowered). Retention is still limited: on a busy PC the oldest events can be overwritten within days, so export the log if you need to keep it.
#   uac: Keep User Account Control switched on
#       risk/why: Only acts when UAC was switched off; takes effect after the next restart.
#   netbios: Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters
#       risk/why: Looking up or browsing machines by their NetBIOS name stops working on the adapters that exist now (very old file shares, printers or NAS boxes reached by a short name). It takes effect when the adapter reconnects or after a restart; adapters added later keep their default.
#   wpad: Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP
#       risk/why: A network that hands out its proxy only through WPAD (some offices and schools) no longer gives it to Windows services and apps that use WinHTTP, so they can lose internet access until a proxy is set by hand. The WinHTTP auto-proxy service itself is left running.
#
# Deliberately NOT changed:
#   bitlocker: BitLocker is not turned on automatically
#       risk/why: It needs a TPM, a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone out of their own data.
#   ntlm: NTLM authentication levels are left as they are
#       risk/why: Stricter levels can break access to older file shares, printers and NAS devices without any warning.
#   accounts_disks: Accounts, passwords, disks, language, licence and product key
#       risk/why: Windows Setup stays fully interactive; the hardening script never touches them.
#   device_guard: Memory Integrity (HVCI), Credential Guard and Exploit Protection are only reported, never turned on
#       risk/why: They depend on the hardware, drivers and apps of each PC and can stop a PC from starting or a program from running; Audit mode shows their state so the owner can decide.
[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Audit', 'Undo')]
    [string]$Mode = 'Apply',
    [switch]$DisableLegacyNetwork,
    [string]$LogPath = (Join-Path $env:windir 'Temp\epma-hardening.log')
)

$ErrorActionPreference = 'Stop'
$script:CountOk = 0
$script:CountSkip = 0
$script:CountWarn = 0
$script:CountFail = 0
$script:CountDiff = 0
$script:CountNa = 0
$script:LogToFile = $true
$script:State = @{}
$script:StateError = ''
$script:StateDir = Join-Path $env:ProgramData 'EPMA'
$script:StatePath = Join-Path $script:StateDir 'hardening-state.json'
$script:AuditBackupPath = Join-Path $script:StateDir 'audit-policy-before.csv'
$script:StateFolderChecked = $false
# Rights that let a principal change a folder or a file: write data or add files, append data or add folders, write
# extended attributes, delete child items, write attributes, delete, change the access list, take ownership, and the
# generic all and write rights.
$script:WriteMask = 0x500D0156
$script:GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# What Undo may touch. The state file is a source of VALUES only: which registry value, attack surface rule, audit
# subcategory, firewall profile, Defender preference or optional feature is put back comes from these tables, which
# are constants of this script. A path or name written in the file is never used as a target.
$script:KnownReg = @{
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = @(0, 1)
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient|EnableMulticast' = @(0, 1)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun' = @(-1, 255)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun' = @(0, 1)
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential' = @(0, 1)
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging' = @(0, 1)
    'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance|fAllowToGetHelp' = @(0, 1)
    'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance|fAllowFullControl' = @(0, 1)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA' = @(0, 1)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp|DisableWpad' = @(0, 1)
}
$script:KnownAsr = @(
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
    'd3e037e1-3eb8-44c8-a917-57927947596d',
    '56a863a9-875e-4185-98a7-b882c64b5ce5',
    'd1e49aac-8f56-4280-b9ba-993a6d77406c',
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
)
$script:KnownAudit = @(
    '{0CCE9215-69AE-11D9-BED3-505054503030}',
    '{0CCE9217-69AE-11D9-BED3-505054503030}',
    '{0CCE9235-69AE-11D9-BED3-505054503030}',
    '{0CCE9237-69AE-11D9-BED3-505054503030}',
    '{0CCE922F-69AE-11D9-BED3-505054503030}',
    '{0CCE922B-69AE-11D9-BED3-505054503030}'
)
$script:KnownFeatures = @('SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')
$script:KnownMp = @('PUAProtection', 'MAPSReporting')
$script:NetbtPattern = '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_\{[0-9A-Fa-f-]{36}\}$'

# Every line goes to the console; the log file gets it as well, unless Setup is running this script (see below).
function Write-Log {
    param([string]$Line)
    Write-Host $Line
    if ($script:LogToFile) {
        try {
            Add-Content -LiteralPath $LogPath -Value $Line -Encoding UTF8
        } catch {
            $script:LogToFile = $false
            Write-Host ('[WARN] cannot write the log file ' + $LogPath + ': ' + $_.Exception.Message)
        }
    }
}

# Apply and Undo: one log line per setting: [OK], [SKIP], [WARN] or [FAIL], what it was, and why. [OK] means the
# value was read back and is in effect; [WARN] means the command did not fail but the value is not in effect.
function Write-Result {
    param([string]$Status, [string]$What, [string]$Why)
    if ($Status -eq 'OK') { $script:CountOk++ }
    elseif ($Status -eq 'SKIP') { $script:CountSkip++ }
    elseif ($Status -eq 'WARN') { $script:CountWarn++ }
    else { $script:CountFail++ }
    Write-Log ('[' + $Status + '] ' + $What + ' (' + $Why + ')')
}

# Audit: [OK] in effect, [DIFF] not in effect, [N/A] cannot be told. With -OptIn a missing opt-in setting is
# reported as [N/A] (it was never requested) and is not counted as a difference.
function Write-Audit {
    param([string]$Verdict, [string]$What, [string]$Detail, [bool]$OptIn = $false)
    if (($Verdict -eq 'DIFF') -and $OptIn -and (-not $DisableLegacyNetwork)) {
        $Verdict = 'NA'
        $Detail = $Detail + '; opt-in setting, not requested (use -DisableLegacyNetwork), not counted'
    }
    if ($Verdict -eq 'OK') {
        $script:CountOk++
        Write-Log ('[OK] ' + $What + ' -- in effect (' + $Detail + ')')
    } elseif ($Verdict -eq 'DIFF') {
        $script:CountDiff++
        Write-Log ('[DIFF] ' + $What + ' -- not in effect (' + $Detail + ')')
    } else {
        $script:CountNa++
        Write-Log ('[N/A] ' + $What + ' -- ' + $Detail)
    }
}

function Write-Info {
    param([string]$Text)
    Write-Log ('[INFO] ' + $Text)
}

# Undo: one line for a setting from the results of the Restore-* calls ('no record' = nothing was recorded; 'not
# restored' = a record exists but putting it back failed: the Restore-* function already logged [WARN] and kept the
# record, so the setting is never reported as "nothing recorded").
function Write-UndoSummary {
    param([string]$What, [string[]]$Results)
    $done = @($Results | Where-Object { ($_ -ne 'no record') -and ($_ -ne 'not restored') })
    $kept = @($Results | Where-Object { $_ -eq 'not restored' })
    if ($done.Count -gt 0) {
        $text = 'put back: ' + ($done -join ', ')
        if ($kept.Count -gt 0) { $text = $text + '; ' + $kept.Count + ' part(s) not put back, see the warnings above' }
        Write-Result 'OK' $What $text
    } elseif ($kept.Count -eq 0) {
        Write-Result 'SKIP' $What 'nothing recorded, this script did not change it'
    }
}

function Get-ChangeText {
    param([bool]$Changed)
    if ($Changed) { return 'changed' }
    return 'already set'
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return 'not set' }
    return [string]$Value
}

# Current value of a registry value or $null when the key or the value does not exist.
function Get-RegDword {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

# ---- State for -Mode Undo --------------------------------------------------------------------------------------
# Before Apply changes a setting, the previous value is written to the state file (a JSON file under ProgramData).
# A value that is already in the file is never overwritten: it is the first value this script ever saw, which is
# what Undo puts back. Audit mode never reads, creates or writes any of this.
#
# The file is only as trustworthy as its folder. The folder is created in ONE step with its protected access list
# (only SYSTEM and Administrators), so there is no moment when another user could own it. A folder that already
# exists is used only after three checks: it is not a junction or symbolic link, its owner is SYSTEM or
# Administrators, and nobody else can write to it. Otherwise Apply and Undo refuse, and Apply changes nothing,
# because without a record there would be no way back. The same folder holds the audit-policy backup.
# On top of that, Undo uses the file for VALUES only (see the tables above) and checks every value.
function Test-TrustedPath {
    param([string]$Path, [bool]$IsFolder)
    # Returns an empty string when the item can be relied on, otherwise the reason it cannot.
    $item = Get-Item -LiteralPath $Path -Force
    if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return 'it is a junction or symbolic link'
    }
    if ($IsFolder -ne [bool]$item.PSIsContainer) { return 'it is not the kind of item expected' }
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (($null -eq $owner) -or ($trusted -notcontains $owner.Value)) {
        return ('its owner is ' + $acl.Owner + ', not SYSTEM or Administrators')
    }
    $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    if ([string]::IsNullOrEmpty($sddl)) { return 'it has no access list, so everyone could change it' }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = [string]$rule.IdentityReference.Value
        if ($trusted -contains $sid) { continue }
        if (([int]$rule.FileSystemRights -band $script:WriteMask) -ne 0) {
            return ('the account ' + $sid + ' is allowed to change it')
        }
    }
    return ''
}

function Assert-TrustedFile {
    param([string]$Path)
    $why = Test-TrustedPath $Path $false
    if ($why -ne '') { throw ('the file ' + $Path + ' cannot be trusted: ' + $why) }
}

function New-StateSecurity {
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    return $security
}

# Throws (with the reason and what to do) when the state folder cannot be trusted. Never fails open.
function Assert-StateFolder {
    $why = Test-TrustedPath $script:StateDir $true
    if ($why -ne '') {
        throw ('the state folder ' + $script:StateDir + ' cannot be trusted: ' + $why + '. As administrator, check who made it, then delete it or rename it and run this script again.')
    }
    $script:StateFolderChecked = $true
}

# Apply: creates the folder with its protected access list in one call, or checks the one that exists. Throws on any
# problem; the callers treat that as fatal.
function Initialize-StateFolder {
    if ($script:StateFolderChecked) { return }
    $present = Get-Item -LiteralPath $script:StateDir -Force -ErrorAction SilentlyContinue
    if ($null -eq $present) {
        [void][System.IO.Directory]::CreateDirectory($script:StateDir, (New-StateSecurity))
    }
    Assert-StateFolder
}

# Reads the state file into $script:State (a hashtable of hashtables). $false when the file exists but is unreadable
# or cannot be trusted.
function Import-State {
    $script:State = @{}
    if ($null -eq (Get-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue)) { return $true }
    try {
        Assert-TrustedFile $script:StatePath
        if ((Get-Item -LiteralPath $script:StatePath -Force).Length -gt 1048576) { throw 'the file is larger than 1 MiB' }
        $raw = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8
        $doc = $raw | ConvertFrom-Json
        if (($null -eq $doc) -or ($doc.version -ne 1) -or ($null -eq $doc.entries)) { throw 'the file is not a version 1 state file' }
        foreach ($p in $doc.entries.PSObject.Properties) {
            if ($p.Value -isnot [System.Management.Automation.PSCustomObject]) { throw ('the record ' + $p.Name + ' is not an object') }
            $h = @{}
            foreach ($q in $p.Value.PSObject.Properties) { $h[$q.Name] = $q.Value }
            $script:State[$p.Name] = $h
        }
        return $true
    } catch {
        $script:State = @{}
        $script:StateError = $_.Exception.Message
        return $false
    }
}

# Undo: a record whose key is not one of the settings this script manages is reported and left alone.
function Test-StateEntries {
    foreach ($k in @($script:State.Keys)) {
        $ok = $false
        if ($k -match '^reg\|(.+)\|([^|]+)$') {
            $ok = ($null -ne (Get-KnownRegRange $Matches[1] $Matches[2]))
        } elseif ($k -match '^asr\|(.+)$') {
            $id = $Matches[1]
            $ok = (($id -match $script:GuidPattern) -and ($script:KnownAsr -contains $id))
        } elseif ($k -match '^audit\|(.+)$') {
            $ok = ($script:KnownAudit -contains $Matches[1])
        } elseif ($k -match '^fw\|(.+)$') {
            $ok = (@('Domain', 'Private', 'Public') -contains $Matches[1])
        } elseif ($k -match '^mp\|(.+)$') {
            $ok = ($script:KnownMp -contains $Matches[1])
        } elseif ($k -match '^feature\|(.+)$') {
            $ok = ($script:KnownFeatures -contains $Matches[1])
        } elseif ($k -eq 'eventlog|Security') {
            $ok = $true
        }
        if (-not $ok) {
            Write-Result 'WARN' 'Unrecognised record in the state file' ('ignored, not a setting this script manages: ' + $k)
        }
    }
}

# Checked readers for a value taken from the state file. Each throws when the value is not what Apply could have written.
function ConvertTo-SafeInt {
    param($Value, [int64]$Min, [int64]$Max, [string]$What)
    if (($Value -isnot [int]) -and ($Value -isnot [long])) { throw ('the recorded ' + $What + ' is not a whole number') }
    $n = [int64]$Value
    if (($n -lt $Min) -or ($n -gt $Max)) { throw ('the recorded ' + $What + ' ' + $n + ' is outside the range ' + $Min + ' to ' + $Max) }
    return $n
}

function Get-RecordBool {
    param($Value, [string]$What)
    if ($Value -isnot [bool]) { throw ('the recorded ' + $What + ' is not true or false') }
    return [bool]$Value
}

function Get-RecordChoice {
    param($Value, [string[]]$Choices, [string]$What)
    $text = [string]$Value
    foreach ($c in $Choices) {
        if ($c -ieq $text) { return $c }
    }
    throw ('the recorded ' + $What + ' is not one this script knows')
}

function Save-State {
    Initialize-StateFolder
    $doc = @{ version = 1; entries = $script:State }
    $json = $doc | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $script:StatePath -Value $json -Encoding UTF8
}

# Records one previous value, but only the first time. If the file cannot be written (or the folder cannot be
# trusted) the exception stops the change that was about to follow: nothing is changed without a way back.
function Add-StateOnce {
    param([string]$Key, [hashtable]$Entry)
    if ($script:State.ContainsKey($Key)) { return }
    $script:State[$Key] = $Entry
    try {
        Save-State
    } catch {
        [void]$script:State.Remove($Key)
        throw
    }
}

function Remove-StateEntry {
    param([string]$Key)
    [void]$script:State.Remove($Key)
    Save-State
}

# The range of DWORD values this script may write or put back for one registry value, or $null when it is not one
# of the values it manages. The NetBIOS option of one network adapter is matched by pattern.
function Get-KnownRegRange {
    param([string]$Path, [string]$Name)
    $k = $Path + '|' + $Name
    if ($script:KnownReg.ContainsKey($k)) { return ,@($script:KnownReg[$k]) }
    # .NET lets $ match before a final line break, so a line break in the key is refused on its own.
    if (($Name -eq 'NetbiosOptions') -and ($Path -match $script:NetbtPattern) -and ($Path -notmatch '[\r\n]')) { return ,@(0, 2) }
    return $null
}

# Writes one DWORD only when it differs; the previous value (or its absence) is recorded first.
# Returns $true when it changed something.
function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    $range = Get-KnownRegRange $Path $Name
    if (($null -eq $range) -or ($Value -lt $range[0]) -or ($Value -gt $range[1])) {
        throw ('internal error: ' + $Name + ' is not a value this script manages')
    }
    $current = $null
    $existed = $false
    $kind = ''
    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $existed = $true
            $current = $item.$Name
            $kind = [string](Get-Item -LiteralPath $Path).GetValueKind($Name)
        }
    }
    if ($existed -and ($kind -eq 'DWord') -and ([int]$current -eq $Value)) { return $false }
    Add-StateOnce ('reg|' + $Path + '|' + $Name) @{ kind = 'reg'; path = $Path; name = $Name; existed = $existed; type = $kind; value = $current } | Out-Null
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    return $true
}

# Puts a registry value back (or removes it when it did not exist). The key and the name come from the caller, which
# passes constants of this script, and are checked against the built-in table again here; the file supplies only the
# earlier value, which is type-checked and range-checked. An empty key that Apply created is left. It never throws:
# when something fails it logs [WARN], KEEPS the record so Undo can be run again, and returns 'not restored'.
# The SMBv1 server value is never written back as 1 (that would bring SMBv1 back): the note gives the manual command.
function Restore-RegValue {
    param([string]$Path, [string]$Name)
    $key = 'reg|' + $Path + '|' + $Name
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    try {
        $range = Get-KnownRegRange $Path $Name
        if ($null -eq $range) { throw ('internal error: ' + $Name + ' is not a value this script manages') }
        $rec = $script:State[$key]
        $existed = Get-RecordBool $rec.existed 'existed flag'
        if ($existed) {
            $kind = Get-RecordChoice $rec.type @('DWord', 'QWord', 'String', 'ExpandString') 'value type'
            if ($kind -eq 'DWord') {
                $val = [int](ConvertTo-SafeInt $rec.value $range[0] $range[1] 'value')
            } elseif ($kind -eq 'QWord') {
                $val = [int64](ConvertTo-SafeInt $rec.value ([int64]::MinValue) ([int64]::MaxValue) 'value')
            } else {
                $val = [string]$rec.value
                if ($val -notmatch '^[\x20-\x7E]{0,260}$') { throw 'the recorded text value is not plain text of at most 260 characters' }
            }
            if (($Name -eq 'SMB1') -and (($kind -ne 'DWord') -or ($val -ne 0))) {
                Remove-StateEntry $key
                Write-Result 'WARN' 'SMBv1 server value not turned back on' ('the earlier value ' + (Format-Value $rec.value) + ' is deliberately not written back, because that would bring SMBv1 back; if you really need it, run as administrator: Set-ItemProperty -Path ' + $Path + ' -Name SMB1 -Value 1')
                return 'not restored'
            }
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $val -PropertyType $kind -Force | Out-Null
            $now = Get-RegDword -Path $Path -Name $Name
            if (($null -eq $now) -or ([string]$now -ne [string]$val)) { throw ($Name + ' reads ' + (Format-Value $now) + ' after it was put back, expected ' + $val) }
            $result = 'restored ' + $Name
        } else {
            if ($null -ne (Get-RegDword -Path $Path -Name $Name)) {
                Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            }
            if ($null -ne (Get-RegDword -Path $Path -Name $Name)) { throw ($Name + ' is still there after the removal') }
            $result = 'removed ' + $Name
        }
        Remove-StateEntry $key
        return $result
    } catch {
        Write-Result 'WARN' ($Name + ' not put back; the record is kept, run Undo again to retry') $_.Exception.Message
        return 'not restored'
    }
}

# State of an optional Windows feature ('Enabled', 'Disabled', 'DisablePending', ...) or $null when it does not exist.
# The list is read once, on first use, and kept: Get-WindowsOptionalFeature is slow and Setup should finish quickly.
# After a feature was changed the kept list is stale (turning the Root feature off can already change its child), so
# -Fresh reads the list again.
$script:Features = $null
$script:FeaturesError = $null
function Get-FeatureState {
    param([string]$Name, [switch]$Fresh)
    if ($Fresh) {
        $script:Features = $null
        $script:FeaturesError = $null
    }
    if ($null -eq $script:Features) {
        $script:Features = @{}
        try {
            foreach ($f in @(Get-WindowsOptionalFeature -Online)) {
                $script:Features[[string]$f.FeatureName] = [string]$f.State
            }
        } catch {
            $script:FeaturesError = $_.Exception.Message
        }
    }
    if ($null -ne $script:FeaturesError) { throw $script:FeaturesError }
    if ($script:Features.ContainsKey($Name)) { return $script:Features[$Name] }
    return $null
}

# An optional feature that is turned off cannot be turned on again by Undo (that could bring back SMBv1 or
# PowerShell 2.0 by accident): Undo only says which command to run.
function Save-FeatureState {
    param([string]$Name, [string]$State)
    Add-StateOnce ('feature|' + $Name) @{ kind = 'feature'; name = $Name; state = $State } | Out-Null
}

function Restore-FeatureState {
    param([string]$Name)
    $key = 'feature|' + $Name
    if (-not $script:State.ContainsKey($key)) { return $null }
    if ($script:KnownFeatures -notcontains $Name) { return $null }
    $rec = $script:State[$key]
    $was = [string]$rec.state
    if ($was -notmatch '^[A-Za-z]{1,40}$') { $was = 'in an unknown state' }
    Remove-StateEntry $key
    return ($Name + ' was ' + $was + ' before; to turn it on again run, as administrator: Enable-WindowsOptionalFeature -Online -FeatureName ' + $Name)
}

# Current action of one attack surface reduction rule (0 off, 1 Block, 2 Audit, 6 Warn) or $null when not listed.
function Get-AsrAction {
    param([string]$Id)
    $pref = Get-MpPreference
    if ($null -eq $pref.AttackSurfaceReductionRules_Ids) { return $null }
    $ids = @($pref.AttackSurfaceReductionRules_Ids)
    $actions = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]$ids[$i] -ieq $Id) { return [int]$actions[$i] }
    }
    return $null
}

function Get-AsrActionName {
    param($Action)
    if ($null -eq $Action) { return 'not set' }
    if ($Action -eq 0) { return 'off' }
    if ($Action -eq 1) { return 'Block' }
    if ($Action -eq 2) { return 'Audit' }
    if ($Action -eq 6) { return 'Warn' }
    return ('action ' + $Action)
}

# Attack surface reduction rule: 'Enabled' (Block) or 'AuditMode'. A rule that is already Block or Warn is
# never weakened to Audit. The earlier action (or "not listed") is recorded first. Returns 'changed' or
# 'already set'; the caller reads the result back.
function Set-AsrRule {
    param([string]$Id, [string]$Action)
    $current = Get-AsrAction $Id
    $wanted = 2
    if ($Action -eq 'Enabled') { $wanted = 1 }
    if ($null -ne $current) {
        if ($current -eq $wanted) { return 'already set' }
        if (($wanted -eq 2) -and (($current -eq 1) -or ($current -eq 6))) { return 'already set' }
    }
    $listed = $true
    $was = -1
    if ($null -eq $current) { $listed = $false } else { $was = $current }
    Add-StateOnce ('asr|' + $Id.ToLower()) @{ kind = 'asr'; id = $Id.ToLower(); listed = $listed; action = $was } | Out-Null
    if ($wanted -eq 1) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions Enabled
    } else {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions AuditMode
    }
    return 'changed'
}

# Puts a rule back to its recorded action (or removes it when it was not listed) and reads the result back. The rule
# id must be a GUID AND one of the rules in $script:KnownAsr (the id written in the file is never used). It never
# throws: on a failure it logs [WARN], keeps the record and returns 'not restored'.
function Restore-AsrRule {
    param([string]$Id)
    $key = 'asr|' + $Id.ToLower()
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    try {
        if (($Id -notmatch $script:GuidPattern) -or ($script:KnownAsr -notcontains $Id)) {
            throw ('internal error: ' + $Id + ' is not a rule this script manages')
        }
        $rec = $script:State[$key]
        $listed = Get-RecordBool $rec.listed 'listed flag'
        $action = -1
        if ($listed) {
            $action = [int](ConvertTo-SafeInt $rec.action 0 6 'rule action')
            $names = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }
            $name = $names[$action]
            if ($null -eq $name) { throw ('the earlier action ' + $action + ' of rule ' + $Id + ' is not one this script knows') }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions $name
        } else {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $Id
        }
        $now = Get-AsrAction $Id
        if ($listed) { $ok = ($now -eq $action) } else { $ok = ($null -eq $now) }
        if (-not $ok) { throw ('rule ' + $Id + ' is not back at its earlier action (Tamper Protection, another antivirus or a Defender that is not ready can block this)') }
        Remove-StateEntry $key
        return ('rule ' + $Id.Substring(0, 8))
    } catch {
        Write-Result 'WARN' ('Attack surface rule ' + $Id + ' not put back; the record is kept, run Undo again to retry') $_.Exception.Message
        return 'not restored'
    }
}

# Windows Firewall: the profile settings of the local store as they were before Apply.
function Save-FirewallState {
    foreach ($p in @(Get-NetFirewallProfile -Profile Domain,Private,Public -PolicyStore PersistentStore)) {
        Add-StateOnce ('fw|' + [string]$p.Name) @{ kind = 'fw'; name = [string]$p.Name; enabled = [string]$p.Enabled; inbound = [string]$p.DefaultInboundAction } | Out-Null
    }
}

# Puts each recorded profile back and reads it back. A part that was recorded as NotConfigured (a Group Policy value)
# cannot be set in the local store, so it is reported as [WARN] and left as it is. It never throws: on a failure it
# logs [WARN], keeps that profile's record and goes on with the next profile.
function Restore-FirewallState {
    $done = @()
    $kept = 0
    foreach ($n in @('Domain', 'Private', 'Public')) {
        $key = 'fw|' + $n
        if (-not $script:State.ContainsKey($key)) { continue }
        try {
            $rec = $script:State[$key]
            $enabled = Get-RecordChoice $rec.enabled @('True', 'False', 'NotConfigured') 'firewall state'
            $inbound = Get-RecordChoice $rec.inbound @('Allow', 'Block', 'NotConfigured') 'inbound action'
            $splat = @{ Profile = $n }
            $left = @()
            if (($enabled -eq 'True') -or ($enabled -eq 'False')) { $splat['Enabled'] = $enabled } else { $left += 'on/off state' }
            if (($inbound -eq 'Allow') -or ($inbound -eq 'Block')) { $splat['DefaultInboundAction'] = $inbound } else { $left += 'inbound action' }
            if ($splat.Count -gt 1) { Set-NetFirewallProfile @splat }
            $now = Get-NetFirewallProfile -Profile $n -PolicyStore PersistentStore
            $wrong = @()
            if ($splat.ContainsKey('Enabled') -and ([string]$now.Enabled -ne $enabled)) { $wrong += 'Enabled is ' + [string]$now.Enabled }
            if ($splat.ContainsKey('DefaultInboundAction') -and ([string]$now.DefaultInboundAction -ne $inbound)) { $wrong += 'DefaultInboundAction is ' + [string]$now.DefaultInboundAction }
            if ($wrong.Count -gt 0) { throw ('read back after setting: ' + ($wrong -join ', ') + '; a Group Policy or another firewall product can win') }
            Remove-StateEntry $key
            if ($left.Count -gt 0) {
                Write-Result 'WARN' ('Firewall profile ' + $n + ' only partly put back') ('the earlier ' + ($left -join ' and ') + ' was NotConfigured, which cannot be set in the local store, so it stays as it is now')
            }
            if ($splat.Count -gt 1) { $done += ('profile ' + $n) } else { $kept++ }
        } catch {
            $kept++
            Write-Result 'WARN' ('Firewall profile ' + $n + ' not put back; the record is kept, run Undo again to retry') $_.Exception.Message
        }
    }
    if ($done.Count -gt 0) { return ($done -join ', ') }
    if ($kept -gt 0) { return 'not restored' }
    return 'no record'
}

# Defender preference (PUAProtection, MAPSReporting): the earlier numeric value.
function Save-DefenderValue {
    param([string]$Name, [int]$Value)
    Add-StateOnce ('mp|' + $Name) @{ kind = 'mp'; name = $Name; value = $Value } | Out-Null
}

function Restore-DefenderValue {
    param([string]$Name)
    $key = 'mp|' + $Name
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    try {
        if ($script:KnownMp -notcontains $Name) { throw ('internal error: ' + $Name + ' is not a preference this script manages') }
        $rec = $script:State[$key]
        $value = [int](ConvertTo-SafeInt $rec.value 0 2 'preference value')
        $splat = @{}
        $splat[$Name] = $value
        Set-MpPreference @splat
        $pref = Get-MpPreference
        if ([int]$pref.$Name -ne $value) { throw ($Name + ' is not back at ' + $value + ' (Tamper Protection or another antivirus can block this)') }
        Remove-StateEntry $key
        return ('restored ' + $Name)
    } catch {
        Write-Result 'WARN' ('Defender ' + $Name + ' not put back; the record is kept, run Undo again to retry') $_.Exception.Message
        return 'not restored'
    }
}

# Advanced audit policy. auditpol prints the words of the Windows language, so only the English words are
# understood; anything else is reported as not known. The whole earlier policy is also saved once with
# "auditpol /backup" (a file that can be restored by hand in any language).
function Get-AuditSetting {
    param([string]$Guid)
    $out = @(& auditpol.exe /get ('/subcategory:' + $Guid) /r)
    $line = ''
    foreach ($l in $out) {
        if (([string]$l).Trim() -ne '') { $line = [string]$l }
    }
    $raw = ''
    $fields = $line.Split(',')
    if (($LASTEXITCODE -eq 0) -and ($fields.Count -ge 6)) { $raw = $fields[4].Trim() }
    $known = $true
    $s = $false
    $f = $false
    if ($raw -eq 'No Auditing') { }
    elseif ($raw -eq 'Success') { $s = $true }
    elseif ($raw -eq 'Failure') { $f = $true }
    elseif ($raw -eq 'Success and Failure') { $s = $true; $f = $true }
    else { $known = $false }
    return @{ raw = $raw; known = $known; success = $s; failure = $f }
}

function Save-AuditBackup {
    Initialize-StateFolder
    if (Test-Path -LiteralPath $script:AuditBackupPath) {
        Assert-TrustedFile $script:AuditBackupPath
        return
    }
    try {
        & auditpol.exe /backup ('/file:' + $script:AuditBackupPath) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw ('auditpol /backup exit code ' + $LASTEXITCODE) }
    } catch {
        Write-Log ('[WARN] could not save the whole earlier audit policy to ' + $script:AuditBackupPath + ': ' + $_.Exception.Message)
    }
}

# Turns on the wanted flags of one subcategory (never turns a flag off); the earlier setting is recorded first.
function Set-AuditSubcategory {
    param([string]$Guid, [bool]$Success, [bool]$Failure)
    $cur = Get-AuditSetting $Guid
    Add-StateOnce ('audit|' + $Guid) @{ kind = 'audit'; guid = $Guid; raw = $cur.raw; known = $cur.known; success = $cur.success; failure = $cur.failure } | Out-Null
    $flags = @()
    if ($Success) { $flags += '/success:enable' }
    if ($Failure) { $flags += '/failure:enable' }
    $out = & auditpol.exe /set ('/subcategory:' + $Guid) @flags | Out-String
    if ($LASTEXITCODE -ne 0) { throw ('auditpol rejected it (exit code ' + $LASTEXITCODE + '): ' + $out.Trim()) }
}

function Restore-AuditSubcategory {
    param([string]$Guid)
    $key = 'audit|' + $Guid
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    try {
        if ($script:KnownAudit -notcontains $Guid) { throw ('internal error: ' + $Guid + ' is not a subcategory this script manages') }
        $rec = $script:State[$key]
        $known = Get-RecordBool $rec.known 'known flag'
        if (-not $known) {
            throw ('the earlier setting of ' + $Guid + ' could not be read when it was recorded, so it is not guessed; restore the whole earlier policy by hand with: auditpol /restore /file:' + $script:AuditBackupPath)
        }
        $s = '/success:disable'
        $f = '/failure:disable'
        if (Get-RecordBool $rec.success 'success flag') { $s = '/success:enable' }
        if (Get-RecordBool $rec.failure 'failure flag') { $f = '/failure:enable' }
        $out = & auditpol.exe /set ('/subcategory:' + $Guid) $s $f | Out-String
        if ($LASTEXITCODE -ne 0) { throw ('auditpol rejected it (exit code ' + $LASTEXITCODE + '): ' + $out.Trim()) }
        Remove-StateEntry $key
        return ('audit ' + $Guid)
    } catch {
        Write-Result 'WARN' ('Audit subcategory ' + $Guid + ' could not be restored; the record is kept, run Undo again to retry') $_.Exception.Message
        return 'not restored'
    }
}

# The Security event log size is only ever raised; Undo never shrinks it (it only reports that).
function Save-EventLogState {
    param([int64]$Bytes)
    Add-StateOnce 'eventlog|Security' @{ kind = 'eventlog'; name = 'Security'; bytes = $Bytes } | Out-Null
}

function Restore-EventLogState {
    $key = 'eventlog|Security'
    if (-not $script:State.ContainsKey($key)) { return $null }
    $rec = $script:State[$key]
    $size = 'an unknown number of'
    try { $size = [string][math]::Round((ConvertTo-SafeInt $rec.bytes 0 1099511627776 'log size') / 1MB) } catch { $size = 'an unknown number of' }
    Remove-StateEntry $key
    return ('Security log size not shrunk (it was ' + $size + ' MiB before Apply and stays as it is)')
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.IsSystem

# Two ways to get here. (1) Windows Setup: SetupComplete.cmd runs this as SYSTEM with no arguments and appends the
# console output to the log file itself, so the script must not write the same lines to the file again.
# (2) An administrator on an installed Windows 11 (harden.cmd): the script writes the log file itself.
# Audit mode changes nothing, so it writes a file only when -LogPath is given on purpose.
if ((-not $PSBoundParameters.ContainsKey('LogPath')) -and ($isSystem -or ($Mode -eq 'Audit'))) {
    $script:LogToFile = $false
}

if (-not $isAdmin) {
    Write-Host '[FAIL] This script must run as administrator: right-click harden.cmd and choose Run as administrator, or start PowerShell as administrator. Nothing was changed.'
    if ($isSystem) { exit 0 }
    exit 1
}

if ($script:LogToFile) {
    try {
        $logDir = Split-Path -Parent $LogPath
        if ($logDir -and (-not (Test-Path -LiteralPath $logDir))) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    } catch {
        $script:LogToFile = $false
        Write-Host ('[WARN] cannot create the folder of the log file ' + $LogPath + ': ' + $_.Exception.Message)
    }
}

Write-Log ('[START] EPMA hardening, mode ' + $Mode + ', ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($Mode -eq 'Audit') {
    Write-Info 'Audit mode: nothing is changed, no state file is read or written.'
    Write-Info 'Audit mode reads the optional features with the DISM cmdlets, and DISM may write its own logs under C:\Windows\Logs\DISM; that is not a configuration change.'
} else {
    Write-Info ('Earlier values are recorded in ' + $script:StatePath)
}

# The folder of the state file comes first. Apply creates it with a protected access list in one step, or checks the
# one that exists; Undo checks the one that exists. Anything that cannot be trusted stops the run before the first
# change (Apply must not change what it cannot record) and before the first value is read (Undo must not replay a
# file that another user could have written).
if ($Mode -ne 'Audit') {
    try {
        if ($Mode -eq 'Apply') {
            Initialize-StateFolder
        } elseif ($null -ne (Get-Item -LiteralPath $script:StateDir -Force -ErrorAction SilentlyContinue)) {
            Assert-StateFolder
        }
    } catch {
        Write-Log ('[FAIL] ' + $_.Exception.Message + ' Nothing was changed.')
        if ($isSystem) { exit 0 }
        exit 1
    }
}

if ($Mode -ne 'Audit') {
    if (-not (Import-State)) {
        if ($Mode -eq 'Undo') {
            Write-Log ('[WARN] the state file ' + $script:StatePath + ' cannot be read (' + $script:StateError + '); nothing was put back.')
            if ($isSystem) { exit 0 }
            exit 1
        }
        # Apply: keep the unreadable file for the owner and start a new record.
        try {
            $aside = $script:StatePath + '.unreadable-' + (Get-Date -Format 'yyyyMMddHHmmss')
            Move-Item -LiteralPath $script:StatePath -Destination $aside -Force
            Write-Log ('[WARN] the state file could not be read (' + $script:StateError + '); it was renamed to ' + $aside + ' and a new one is started')
        } catch {
            Write-Log ('[FAIL] the state file ' + $script:StatePath + ' cannot be read and cannot be set aside (' + $_.Exception.Message + '); nothing was changed, because without a record there would be no way back.')
            if ($isSystem) { exit 0 }
            exit 1
        }
    } elseif ($Mode -eq 'Undo') {
        if ($script:State.Count -eq 0) {
            Write-Info 'no earlier values are recorded (there is no state file or it is empty): every setting will be skipped'
        } else {
            Test-StateEntries
        }
    }
}

# setting: smb1
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0
        $note = 'server side already off'
        if ($c1) { $note = 'server side turned off' }
        $restart = $false
        $state = Get-FeatureState 'SMB1Protocol'
        if ($null -eq $state) {
            $note = $note + '; optional feature not present'
        } elseif ($state -eq 'Enabled') {
            Save-FeatureState 'SMB1Protocol' $state
            Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
            # Read the state again: with -NoRestart it often reads DisablePending until the next restart.
            $after = Get-FeatureState 'SMB1Protocol' -Fresh
            if (@('DisablePending', 'EnablePending') -contains $after) {
                $restart = $true
                $note = $note + '; optional feature disabled but a restart is needed to finish it'
            } elseif (($after -eq 'Disabled') -or ($after -eq 'DisabledWithPayloadRemoved')) {
                $note = $note + '; optional feature disabled'
            } else {
                throw ('the optional feature SMB1Protocol is still ' + (Format-Value $after) + ' after it was turned off')
            }
        } elseif (@('DisablePending', 'EnablePending') -contains $state) {
            $restart = $true
            $note = $note + '; optional feature has a change pending, a restart is needed'
        } else {
            $note = $note + '; optional feature already off'
        }
        if ($restart) {
            Write-Result 'WARN' 'Turn off SMBv1 (obsolete file-sharing protocol) needs a restart' $note
        } else {
            Write-Result 'OK' 'Turn off SMBv1 (obsolete file-sharing protocol)' $note
        }
    } catch {
        Write-Result 'FAIL' 'Turn off SMBv1 (obsolete file-sharing protocol)' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        $state = Get-FeatureState 'SMB1Protocol'
        $bad = @()
        if (($null -eq $cur) -or ([int]$cur -ne 0)) { $bad += 'SMB1 server value is ' + (Format-Value $cur) + ', wanted 0' }
        if ($state -eq 'Enabled') { $bad += 'optional feature SMB1Protocol is Enabled' }
        elseif (@('DisablePending', 'EnablePending') -contains $state) { $bad += 'optional feature SMB1Protocol is ' + $state + ', a restart is needed' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Turn off SMBv1 (obsolete file-sharing protocol)' 'SMB1 server value is 0 and the optional feature is off or not present'
        } else {
            Write-Audit 'DIFF' 'Turn off SMBv1 (obsolete file-sharing protocol)' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'Turn off SMBv1 (obsolete file-sharing protocol)' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        Write-UndoSummary 'Turn off SMBv1 (obsolete file-sharing protocol)' $r
        # An optional feature that was turned off is NOT turned on again here: that would bring SMBv1 back.
        $note = Restore-FeatureState 'SMB1Protocol'
        if ($null -ne $note) { Write-Result 'WARN' 'Turn off SMBv1 (obsolete file-sharing protocol) (optional feature not turned on again)' $note }
    } catch {
        Write-Result 'WARN' 'Turn off SMBv1 (obsolete file-sharing protocol) not put back' $_.Exception.Message
    }
}

# setting: llmnr
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
        Write-Result 'OK' 'Turn off LLMNR name lookups' (Get-ChangeText ($c1))
    } catch {
        Write-Result 'FAIL' 'Turn off LLMNR name lookups' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        if (($null -ne $cur) -and ([int]$cur -eq 0)) { $good += 'EnableMulticast is 0' }
        else { $bad += 'EnableMulticast is ' + (Format-Value $cur) + ', wanted 0' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Turn off LLMNR name lookups' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'Turn off LLMNR name lookups' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'Turn off LLMNR name lookups' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        Write-UndoSummary 'Turn off LLMNR name lookups' $r
    } catch {
        Write-Result 'WARN' 'Turn off LLMNR name lookups not put back' $_.Exception.Message
    }
}

# setting: autorun
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
        $c2 = Set-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1
        Write-Result 'OK' 'Turn off AutoRun and AutoPlay on every drive type' (Get-ChangeText ($c1 -or $c2))
    } catch {
        Write-Result 'FAIL' 'Turn off AutoRun and AutoPlay on every drive type' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
        if (($null -ne $cur) -and ([int]$cur -eq 255)) { $good += 'NoDriveTypeAutoRun is 255' }
        else { $bad += 'NoDriveTypeAutoRun is ' + (Format-Value $cur) + ', wanted 255' }
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun'
        if (($null -ne $cur) -and ([int]$cur -eq 1)) { $good += 'NoAutorun is 1' }
        else { $bad += 'NoAutorun is ' + (Format-Value $cur) + ', wanted 1' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Turn off AutoRun and AutoPlay on every drive type' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'Turn off AutoRun and AutoPlay on every drive type' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'Turn off AutoRun and AutoPlay on every drive type' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun'
        Write-UndoSummary 'Turn off AutoRun and AutoPlay on every drive type' $r
    } catch {
        Write-Result 'WARN' 'Turn off AutoRun and AutoPlay on every drive type not put back' $_.Exception.Message
    }
}

# setting: firewall
if ($Mode -eq 'Apply') {
    try {
        $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
        $todo = @($profiles | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
        $changedNote = 'already set'
        if ($todo.Count -gt 0) {
            Save-FirewallState
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
            $changedNote = 'changed on ' + $todo.Count + ' profile(s)'
        }
        # Read the profiles back: "no error" is not the same as "in effect" (a Group Policy or another firewall can win).
        $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
        $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
        if ($off.Count -eq 0) {
            Write-Result 'OK' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' $changedNote
        } else {
            Write-Result 'WARN' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it not in effect' ('still off or open on ' + $off.Count + ' profile(s); likely reason: Group Policy, another firewall product or the firewall service not ready yet')
        }
    } catch {
        Write-Result 'FAIL' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
        $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
        if ($off.Count -eq 0) {
            Write-Audit 'OK' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' 'all three profiles are on with inbound blocked'
        } else {
            Write-Audit 'DIFF' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' ('off or open on ' + $off.Count + ' of ' + $after.Count + ' profile(s): ' + (($off | ForEach-Object { [string]$_.Name }) -join ', '))
        }
    } catch {
        Write-Audit 'NA' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-FirewallState
        Write-UndoSummary 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it' $r
    } catch {
        Write-Result 'WARN' 'Windows Firewall on for all network profiles, inbound blocked unless a rule allows it not put back' $_.Exception.Message
    }
}

# setting: defender_cloud
if ($Mode -eq 'Apply') {
    try {
        if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Result 'SKIP' 'Defender: block potentially unwanted apps and turn cloud protection on' 'Defender cmdlets not available'
        } else {
            $pref = Get-MpPreference
            $changed = @()
            if ([int]$pref.PUAProtection -ne 1) {
                Save-DefenderValue 'PUAProtection' ([int]$pref.PUAProtection)
                Set-MpPreference -PUAProtection Enabled
                $changed += 'PUA protection'
            }
            if ([int]$pref.MAPSReporting -ne 2) {
                Save-DefenderValue 'MAPSReporting' ([int]$pref.MAPSReporting)
                Set-MpPreference -MAPSReporting Advanced
                $changed += 'cloud protection'
            }
            # Read the values back: the cmdlets can return without an error and still change nothing.
            $after = Get-MpPreference
            $missing = @()
            if ([int]$after.PUAProtection -ne 1) { $missing += 'PUA protection' }
            if ([int]$after.MAPSReporting -ne 2) { $missing += 'cloud protection' }
            if ($missing.Count -gt 0) {
                Write-Result 'WARN' 'Defender: block potentially unwanted apps and turn cloud protection on not in effect' (($missing -join ', ') + ' still off; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
            } elseif ($changed.Count -eq 0) {
                Write-Result 'OK' 'Defender: block potentially unwanted apps and turn cloud protection on' 'already set'
            } else {
                Write-Result 'OK' 'Defender: block potentially unwanted apps and turn cloud protection on' ('turned on: ' + ($changed -join ', '))
            }
        }
    } catch {
        Write-Result 'FAIL' 'Defender: block potentially unwanted apps and turn cloud protection on' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Audit 'NA' 'Defender: block potentially unwanted apps and turn cloud protection on' 'Defender cmdlets not available'
        } else {
            $pref = Get-MpPreference
            $bad = @()
            if ([int]$pref.PUAProtection -ne 1) { $bad += 'PUA protection is ' + [int]$pref.PUAProtection + ', wanted 1' }
            if ([int]$pref.MAPSReporting -ne 2) { $bad += 'cloud protection (MAPS) is ' + [int]$pref.MAPSReporting + ', wanted 2' }
            if ($bad.Count -eq 0) {
                Write-Audit 'OK' 'Defender: block potentially unwanted apps and turn cloud protection on' 'PUA protection and cloud protection are on'
            } else {
                Write-Audit 'DIFF' 'Defender: block potentially unwanted apps and turn cloud protection on' ($bad -join '; ')
            }
        }
    } catch {
        Write-Audit 'NA' 'Defender: block potentially unwanted apps and turn cloud protection on' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-DefenderValue 'PUAProtection'
        $r += Restore-DefenderValue 'MAPSReporting'
        Write-UndoSummary 'Defender: block potentially unwanted apps and turn cloud protection on' $r
    } catch {
        Write-Result 'WARN' 'Defender: block potentially unwanted apps and turn cloud protection on not put back' ($_.Exception.Message + ' (Tamper Protection or another antivirus can block this)')
    }
}

# setting: asr_lsass
if ($Mode -eq 'Apply') {
    try {
        if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Result 'SKIP' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' 'Defender cmdlets not available'
        } else {
            $ruleId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            $r = Set-AsrRule -Id $ruleId -Action 'Enabled'
            $now = Get-AsrAction $ruleId
            if ($now -eq 1) {
                Write-Result 'OK' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' $r
            } else {
                Write-Result 'WARN' 'Defender attack surface rule in Block mode: no credential stealing from LSASS not in effect' 'rule is not in Block mode; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet'
            }
        }
    } catch {
        Write-Result 'FAIL' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Audit 'NA' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' 'Defender cmdlets not available'
        } else {
            $now = Get-AsrAction '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            if ($now -eq 1) {
                Write-Audit 'OK' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' 'the rule is in Block mode'
            } else {
                Write-Audit 'DIFF' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' ('the rule action is: ' + (Get-AsrActionName $now))
            }
        }
    } catch {
        Write-Audit 'NA' 'Defender attack surface rule in Block mode: no credential stealing from LSASS' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-AsrRule '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        Write-UndoSummary 'Defender attack surface rule in Block mode: no credential stealing from LSASS' $r
    } catch {
        Write-Result 'WARN' 'Defender attack surface rule in Block mode: no credential stealing from LSASS not put back' $_.Exception.Message
    }
}

# setting: asr_audit
if ($Mode -eq 'Apply') {
    try {
        if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Result 'SKIP' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' 'Defender cmdlets not available'
        } else {
            $rules = @(
                'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
                'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
                '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
                'd3e037e1-3eb8-44c8-a917-57927947596d'
            )
            $applied = 0
            $missing = 0
            foreach ($id in $rules) {
                $r = Set-AsrRule -Id $id -Action 'AuditMode'
                if ($r -eq 'changed') { $applied++ }
                # In effect when the rule is in Audit mode, or already stricter (Block 1 or Warn 6).
                $now = Get-AsrAction $id
                if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) { $missing++ }
            }
            if ($missing -gt 0) {
                Write-Result 'WARN' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads not in effect' ('' + $missing + ' of ' + $rules.Count + ' rules are not active; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
            } else {
                Write-Result 'OK' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' ('' + $applied + ' of ' + $rules.Count + ' rules changed, the others were already set')
            }
        }
    } catch {
        Write-Result 'FAIL' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Audit 'NA' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' 'Defender cmdlets not available'
        } else {
            $rules = @(
                'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
                'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
                '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
                'd3e037e1-3eb8-44c8-a917-57927947596d'
            )
            $off = @()
            foreach ($id in $rules) {
                $now = Get-AsrAction $id
                if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) { $off += $id + ' (' + (Get-AsrActionName $now) + ')' }
            }
            if ($off.Count -eq 0) {
                Write-Audit 'OK' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' ('all ' + $rules.Count + ' rules are in Audit mode or stricter')
            } else {
                Write-Audit 'DIFF' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' ('' + $off.Count + ' of ' + $rules.Count + ' rules not active: ' + ($off -join ', '))
            }
        }
    } catch {
        Write-Audit 'NA' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        foreach ($id in @(
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
            'd3e037e1-3eb8-44c8-a917-57927947596d'
        )) {
            $r += Restore-AsrRule $id
        }
        Write-UndoSummary 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads' $r
    } catch {
        Write-Result 'WARN' 'Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads not put back' $_.Exception.Message
    }
}

# setting: asr_audit_extra
if ($Mode -eq 'Apply') {
    try {
        if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Result 'SKIP' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' 'Defender cmdlets not available'
        } else {
            $rules = @(
                '56a863a9-875e-4185-98a7-b882c64b5ce5',
                'd1e49aac-8f56-4280-b9ba-993a6d77406c',
                'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
            )
            $applied = 0
            $missing = 0
            foreach ($id in $rules) {
                $r = Set-AsrRule -Id $id -Action 'AuditMode'
                if ($r -eq 'changed') { $applied++ }
                # In effect when the rule is in Audit mode, or already stricter (Block 1 or Warn 6).
                $now = Get-AsrAction $id
                if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) { $missing++ }
            }
            if ($missing -gt 0) {
                Write-Result 'WARN' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives not in effect' ('' + $missing + ' of ' + $rules.Count + ' rules are not active; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
            } else {
                Write-Result 'OK' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' ('' + $applied + ' of ' + $rules.Count + ' rules changed, the others were already set')
            }
        }
    } catch {
        Write-Result 'FAIL' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Audit 'NA' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' 'Defender cmdlets not available'
        } else {
            $rules = @(
                '56a863a9-875e-4185-98a7-b882c64b5ce5',
                'd1e49aac-8f56-4280-b9ba-993a6d77406c',
                'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
            )
            $off = @()
            foreach ($id in $rules) {
                $now = Get-AsrAction $id
                if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) { $off += $id + ' (' + (Get-AsrActionName $now) + ')' }
            }
            if ($off.Count -eq 0) {
                Write-Audit 'OK' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' ('all ' + $rules.Count + ' rules are in Audit mode or stricter')
            } else {
                Write-Audit 'DIFF' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' ('' + $off.Count + ' of ' + $rules.Count + ' rules not active: ' + ($off -join ', '))
            }
        }
    } catch {
        Write-Audit 'NA' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        foreach ($id in @(
            '56a863a9-875e-4185-98a7-b882c64b5ce5',
            'd1e49aac-8f56-4280-b9ba-993a6d77406c',
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        )) {
            $r += Restore-AsrRule $id
        }
        Write-UndoSummary 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives' $r
    } catch {
        Write-Result 'WARN' 'Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives not put back' $_.Exception.Message
    }
}

# setting: wdigest
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
        Write-Result 'OK' 'Do not keep plain-text WDigest credentials in memory' (Get-ChangeText ($c1))
    } catch {
        Write-Result 'FAIL' 'Do not keep plain-text WDigest credentials in memory' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
        if ($null -eq $cur) { $good += 'UseLogonCredential is not set (the Windows default is already 0)' }
        elseif ([int]$cur -eq 0) { $good += 'UseLogonCredential is 0' }
        else { $bad += 'UseLogonCredential is ' + (Format-Value $cur) + ', wanted 0' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Do not keep plain-text WDigest credentials in memory' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'Do not keep plain-text WDigest credentials in memory' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'Do not keep plain-text WDigest credentials in memory' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
        Write-UndoSummary 'Do not keep plain-text WDigest credentials in memory' $r
    } catch {
        Write-Result 'WARN' 'Do not keep plain-text WDigest credentials in memory not put back' $_.Exception.Message
    }
}

# setting: ps_logging
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
        Write-Result 'OK' 'PowerShell script block logging' (Get-ChangeText ($c1))
    } catch {
        Write-Result 'FAIL' 'PowerShell script block logging' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
        if (($null -ne $cur) -and ([int]$cur -eq 1)) { $good += 'EnableScriptBlockLogging is 1' }
        else { $bad += 'EnableScriptBlockLogging is ' + (Format-Value $cur) + ', wanted 1' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'PowerShell script block logging' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'PowerShell script block logging' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'PowerShell script block logging' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
        Write-UndoSummary 'PowerShell script block logging' $r
    } catch {
        Write-Result 'WARN' 'PowerShell script block logging not put back' $_.Exception.Message
    }
}

# setting: ps2
if ($Mode -eq 'Apply') {
    try {
        $found = $false
        $disabled = @()
        $restart = @()
        $failed = @()
        $fresh = $false
        foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
            # One feature at a time, each in its own try/catch: turning the Root feature off can already turn the child
            # feature off, so the state is read again before the second one, and an error is judged by the state it left.
            try {
                $state = Get-FeatureState $name -Fresh:$fresh
                if ($null -ne $state) {
                    $found = $true
                    if ($state -eq 'Enabled') {
                        Save-FeatureState $name $state
                        Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart | Out-Null
                        $fresh = $true
                        $after = Get-FeatureState $name -Fresh
                        if (@('DisablePending', 'EnablePending') -contains $after) {
                            $restart += $name
                        } elseif (($after -eq 'Disabled') -or ($after -eq 'DisabledWithPayloadRemoved')) {
                            $disabled += $name
                        } else {
                            throw ('the feature is still ' + (Format-Value $after) + ' after it was turned off')
                        }
                    } elseif (@('DisablePending', 'EnablePending') -contains $state) {
                        $restart += $name
                    }
                }
            } catch {
                $why = $_.Exception.Message
                $fresh = $true
                $again = $null
                try { $again = Get-FeatureState $name -Fresh } catch { $again = $null }
                if (($again -eq 'Disabled') -or ($again -eq 'DisabledWithPayloadRemoved')) {
                    $disabled += $name
                } elseif ($again -eq 'DisablePending') {
                    $restart += $name
                } else {
                    $failed += ($name + ': ' + $why)
                }
            }
        }
        if ($failed.Count -gt 0) {
            Write-Result 'FAIL' 'Disable the PowerShell 2.0 optional feature' ($failed -join ' | ')
        } elseif ($restart.Count -gt 0) {
            Write-Result 'WARN' 'Disable the PowerShell 2.0 optional feature needs a restart' ('change pending for ' + ($restart -join ', ') + '; restart Windows to finish turning the feature off')
        } elseif (-not $found) {
            Write-Result 'SKIP' 'Disable the PowerShell 2.0 optional feature' 'feature not present on this Windows build'
        } elseif ($disabled.Count -gt 0) {
            Write-Result 'OK' 'Disable the PowerShell 2.0 optional feature' 'feature disabled'
        } else {
            Write-Result 'OK' 'Disable the PowerShell 2.0 optional feature' 'already off'
        }
    } catch {
        Write-Result 'FAIL' 'Disable the PowerShell 2.0 optional feature' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $found = $false
        $on = @()
        foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
            $state = Get-FeatureState $name
            if ($null -ne $state) {
                $found = $true
                if ($state -eq 'Enabled') { $on += $name }
                elseif (@('DisablePending', 'EnablePending') -contains $state) { $on += ($name + ' (' + $state + ', a restart is needed)') }
            }
        }
        if (-not $found) {
            Write-Audit 'NA' 'Disable the PowerShell 2.0 optional feature' 'feature not present on this Windows build'
        } elseif ($on.Count -eq 0) {
            Write-Audit 'OK' 'Disable the PowerShell 2.0 optional feature' 'the feature is off'
        } else {
            Write-Audit 'DIFF' 'Disable the PowerShell 2.0 optional feature' ('still enabled: ' + ($on -join ', '))
        }
    } catch {
        Write-Audit 'NA' 'Disable the PowerShell 2.0 optional feature' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $notes = @()
        foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
            $n = Restore-FeatureState $name
            if ($null -ne $n) { $notes += $n }
        }
        if ($notes.Count -eq 0) {
            Write-Result 'SKIP' 'Disable the PowerShell 2.0 optional feature' 'nothing recorded, this script did not change it'
        } else {
            Write-Result 'WARN' 'Disable the PowerShell 2.0 optional feature (optional feature not turned on again)' ($notes -join ' | ')
        }
    } catch {
        Write-Result 'WARN' 'Disable the PowerShell 2.0 optional feature not put back' $_.Exception.Message
    }
}

# setting: remote_assist
if ($Mode -eq 'Apply') {
    try {
        $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
        $c2 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl' -Value 0
        Write-Result 'OK' 'Turn off Remote Assistance invitations' (Get-ChangeText ($c1 -or $c2))
    } catch {
        Write-Result 'FAIL' 'Turn off Remote Assistance invitations' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
        if (($null -ne $cur) -and ([int]$cur -eq 0)) { $good += 'fAllowToGetHelp is 0' }
        else { $bad += 'fAllowToGetHelp is ' + (Format-Value $cur) + ', wanted 0' }
        $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl'
        if (($null -ne $cur) -and ([int]$cur -eq 0)) { $good += 'fAllowFullControl is 0' }
        else { $bad += 'fAllowFullControl is ' + (Format-Value $cur) + ', wanted 0' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Turn off Remote Assistance invitations' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'Turn off Remote Assistance invitations' ($bad -join '; ')
        }
    } catch {
        Write-Audit 'NA' 'Turn off Remote Assistance invitations' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
        $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl'
        Write-UndoSummary 'Turn off Remote Assistance invitations' $r
    } catch {
        Write-Result 'WARN' 'Turn off Remote Assistance invitations not put back' $_.Exception.Message
    }
}

# setting: audit
if ($Mode -eq 'Apply') {
    try {
        $items = @(
            @('{0CCE9215-69AE-11D9-BED3-505054503030}', 'Logon', $true, $true),
            @('{0CCE9217-69AE-11D9-BED3-505054503030}', 'Account Lockout', $true, $true),
            @('{0CCE9235-69AE-11D9-BED3-505054503030}', 'User Account Management', $true, $true),
            @('{0CCE9237-69AE-11D9-BED3-505054503030}', 'Security Group Management', $true, $true),
            @('{0CCE922F-69AE-11D9-BED3-505054503030}', 'Audit Policy Change', $true, $true),
            @('{0CCE922B-69AE-11D9-BED3-505054503030}', 'Process Creation', $true, $false)
        )
        $bad = 0
        $changed = 0
        $backedUp = $false
        foreach ($item in $items) {
            $cur = Get-AuditSetting $item[0]
            # Already enough (or stricter) is left alone; an unreadable setting is set again.
            $satisfied = $cur.known -and ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
            if (-not $satisfied) {
                try {
                    if (-not $backedUp) {
                        Save-AuditBackup
                        $backedUp = $true
                    }
                    Set-AuditSubcategory $item[0] $item[2] $item[3]
                    $changed++
                } catch {
                    $bad++
                    Write-Result 'FAIL' ('Audit subcategory ' + $item[1] + ' ' + $item[0]) ($_.Exception.Message + ' List valid GUIDs with: auditpol /list /subcategory:* /v')
                }
            }
        }
        # The Security log wraps quickly with these events, so raise its maximum size to 128 MiB. Only ever raised.
        $wantBytes = 134217728
        $sizeOk = $true
        $sizeNote = ''
        try {
            $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
            if ($oldBytes -ge $wantBytes) {
                $sizeNote = 'Security log size left at ' + [math]::Round($oldBytes / 1MB) + ' MiB (already 128 MiB or more)'
            } else {
                Save-EventLogState $oldBytes
                & wevtutil.exe sl Security ('/ms:' + $wantBytes) | Out-Null
                $newBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
                if ($newBytes -ge $wantBytes) {
                    $sizeNote = 'Security log size raised from ' + [math]::Round($oldBytes / 1MB) + ' MiB to ' + [math]::Round($newBytes / 1MB) + ' MiB'
                } else {
                    $sizeOk = $false
                    $sizeNote = 'Security log size is still ' + [math]::Round($newBytes / 1MB) + ' MiB (was ' + [math]::Round($oldBytes / 1MB) + ' MiB); a Group Policy may control it'
                }
            }
        } catch {
            $sizeOk = $false
            $sizeNote = 'could not raise the Security log size: ' + $_.Exception.Message
        }
        if (($bad -gt 0) -or (-not $sizeOk)) {
            Write-Result 'WARN' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB not fully in effect' ('' + $bad + ' of ' + $items.Count + ' subcategories rejected; ' + $sizeNote)
        } else {
            Write-Result 'OK' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' ('' + $items.Count + ' subcategories in effect (' + $changed + ' changed); ' + $sizeNote)
        }
    } catch {
        Write-Result 'FAIL' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $items = @(
            @('{0CCE9215-69AE-11D9-BED3-505054503030}', 'Logon', $true, $true),
            @('{0CCE9217-69AE-11D9-BED3-505054503030}', 'Account Lockout', $true, $true),
            @('{0CCE9235-69AE-11D9-BED3-505054503030}', 'User Account Management', $true, $true),
            @('{0CCE9237-69AE-11D9-BED3-505054503030}', 'Security Group Management', $true, $true),
            @('{0CCE922F-69AE-11D9-BED3-505054503030}', 'Audit Policy Change', $true, $true),
            @('{0CCE922B-69AE-11D9-BED3-505054503030}', 'Process Creation', $true, $false)
        )
        $bad = @()
        $unknown = 0
        foreach ($item in $items) {
            $cur = Get-AuditSetting $item[0]
            if (-not $cur.known) {
                $unknown++
            } else {
                $satisfied = ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
                if (-not $satisfied) { $bad += $item[1] + ' is: ' + $cur.raw }
            }
        }
        $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
        if ($oldBytes -lt 134217728) { $bad += 'Security log size is ' + [math]::Round($oldBytes / 1MB) + ' MiB, wanted 128 MiB or more' }
        if ($bad.Count -gt 0) {
            Write-Audit 'DIFF' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' ($bad -join '; ')
        } elseif ($unknown -gt 0) {
            Write-Audit 'NA' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' ('the auditpol output of ' + $unknown + ' subcategories could not be read (a non-English Windows prints other words)')
        } else {
            Write-Audit 'OK' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' ('all ' + $items.Count + ' subcategories are set; Security log is ' + [math]::Round($oldBytes / 1MB) + ' MiB')
        }
    } catch {
        Write-Audit 'NA' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        foreach ($guid in @(
            '{0CCE9215-69AE-11D9-BED3-505054503030}',
            '{0CCE9217-69AE-11D9-BED3-505054503030}',
            '{0CCE9235-69AE-11D9-BED3-505054503030}',
            '{0CCE9237-69AE-11D9-BED3-505054503030}',
            '{0CCE922F-69AE-11D9-BED3-505054503030}',
            '{0CCE922B-69AE-11D9-BED3-505054503030}'
        )) {
            # Restore-AuditSubcategory never throws: it logs [WARN] could not be restored, keeps the record and returns 'not restored'.
            $r += Restore-AuditSubcategory $guid
        }
        $sizeNote = Restore-EventLogState
        if ($null -ne $sizeNote) { $r += $sizeNote }
        Write-UndoSummary 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB' $r
    } catch {
        Write-Result 'WARN' 'Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB not put back' $_.Exception.Message
    }
}

# setting: uac
if ($Mode -eq 'Apply') {
    try {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $cur = Get-RegDword -Path $key -Name 'EnableLUA'
        if (($null -ne $cur) -and ([int]$cur -eq 0)) {
            Set-RegDword -Path $key -Name 'EnableLUA' -Value 1 | Out-Null
            Write-Result 'OK' 'Keep User Account Control switched on' 'was off, turned on (effective after the next restart)'
        } else {
            Write-Result 'OK' 'Keep User Account Control switched on' 'already on, left unchanged'
        }
    } catch {
        Write-Result 'FAIL' 'Keep User Account Control switched on' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
        if (($null -ne $cur) -and ([int]$cur -eq 0)) {
            Write-Audit 'DIFF' 'Keep User Account Control switched on' 'EnableLUA is 0, so User Account Control is off'
        } else {
            Write-Audit 'OK' 'Keep User Account Control switched on' ('EnableLUA is ' + (Format-Value $cur) + ' (not 0)')
        }
    } catch {
        Write-Audit 'NA' 'Keep User Account Control switched on' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
        Write-UndoSummary 'Keep User Account Control switched on' $r
    } catch {
        Write-Result 'WARN' 'Keep User Account Control switched on not put back' $_.Exception.Message
    }
}

# setting: netbios
if ($Mode -eq 'Apply') {
    try {
        if (-not $DisableLegacyNetwork) {
            Write-Result 'SKIP' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' 'opt-in, not requested (run with -DisableLegacyNetwork)'
        } else {
            $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            $names = @()
            if (Test-Path -LiteralPath $base) {
                $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
            }
            if ($names.Count -eq 0) {
                Write-Result 'SKIP' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' 'no network interfaces found in the NetBT settings'
            } else {
                # NetbiosOptions: 0 = use the DHCP setting, 1 = on, 2 = off. Interfaces added later keep their default.
                $changed = 0
                foreach ($n in $names) {
                    if (Set-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions' -Value 2) { $changed++ }
                }
                Write-Result 'OK' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' ('' + $changed + ' of ' + $names.Count + ' interfaces changed, the others were already set; effective after the adapters reconnect or after a restart')
            }
        }
    } catch {
        Write-Result 'FAIL' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        $names = @()
        if (Test-Path -LiteralPath $base) {
            $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
        }
        if ($names.Count -eq 0) {
            Write-Audit 'NA' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' 'no network interfaces found in the NetBT settings'
        } else {
            $on = @()
            foreach ($n in $names) {
                $cur = Get-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions'
                if (($null -eq $cur) -or ([int]$cur -ne 2)) { $on += $n }
            }
            if ($on.Count -eq 0) {
                Write-Audit 'OK' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' ('NetBIOS over TCP/IP is off on all ' + $names.Count + ' interfaces')
            } else {
                Write-Audit 'DIFF' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' ('' + $on.Count + ' of ' + $names.Count + ' interfaces still use NetBIOS over TCP/IP') -OptIn $true
            }
        }
    } catch {
        Write-Audit 'NA' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        foreach ($k in @($script:State.Keys)) {
            # The key names come from the state file, so each one must match the NetBT interface pattern; the value name is
            # a constant. Nothing else in the file decides what is touched (records that do not match are reported).
            if ($k -match '^reg\|(.+)\|NetbiosOptions$') {
                $ifaceKey = $Matches[1]
                if ($ifaceKey -match $script:NetbtPattern) {
                    $r += Restore-RegValue -Path $ifaceKey -Name 'NetbiosOptions'
                }
            }
        }
        if ($r.Count -eq 0) { $r += 'no record' }
        Write-UndoSummary 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters' $r
    } catch {
        Write-Result 'WARN' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters not put back' $_.Exception.Message
    }
}

# setting: wpad
if ($Mode -eq 'Apply') {
    try {
        if (-not $DisableLegacyNetwork) {
            Write-Result 'SKIP' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' 'opt-in, not requested (run with -DisableLegacyNetwork)'
        } else {
            $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Value 1
            Write-Result 'OK' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' (Get-ChangeText ($c1))
        }
    } catch {
        Write-Result 'FAIL' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' $_.Exception.Message
    }
} elseif ($Mode -eq 'Audit') {
    try {
        $good = @()
        $bad = @()
        $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad'
        if (($null -ne $cur) -and ([int]$cur -eq 1)) { $good += 'DisableWpad is 1' }
        else { $bad += 'DisableWpad is ' + (Format-Value $cur) + ', wanted 1' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' ($good -join '; ')
        } else {
            Write-Audit 'DIFF' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' ($bad -join '; ') -OptIn $true
        }
    } catch {
        Write-Audit 'NA' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' ('could not be checked: ' + $_.Exception.Message)
    }
} else {
    try {
        $r = @()
        $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad'
        Write-UndoSummary 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP' $r
    } catch {
        Write-Result 'WARN' 'Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP not put back' $_.Exception.Message
    }
}

if ($Mode -eq 'Audit') {
    Write-Log ''
    Write-Log '--- Read-only information (reported only; this script never turns these on) ---'

    # BitLocker status of the system drive.
    try {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
            Write-Info ('BitLocker on ' + $env:SystemDrive + ' protection ' + (Format-Value $vol.ProtectionStatus) + ', volume status ' + (Format-Value $vol.VolumeStatus) + ', method ' + (Format-Value $vol.EncryptionMethod))
        } else {
            Write-Info 'BitLocker: the BitLocker cmdlets are not available on this Windows edition'
        }
    } catch {
        Write-Info ('BitLocker: cannot read the status (' + $_.Exception.Message + ')')
    }

    # TPM.
    try {
        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
            $tpm = Get-Tpm
            Write-Info ('TPM: present ' + (Format-Value $tpm.TpmPresent) + ', ready ' + (Format-Value $tpm.TpmReady) + ', enabled ' + (Format-Value $tpm.TpmEnabled))
        } else {
            Write-Info 'TPM: the Get-Tpm cmdlet is not available'
        }
    } catch {
        Write-Info ('TPM: cannot read the status (' + $_.Exception.Message + ')')
    }

    # Secure Boot: the cmdlet throws on a PC that boots in legacy BIOS mode or that does not support it.
    try {
        if (Confirm-SecureBootUEFI) {
            Write-Info 'Secure Boot: on'
        } else {
            Write-Info 'Secure Boot: off'
        }
    } catch {
        Write-Info ('Secure Boot: cannot tell (' + $_.Exception.Message + ')')
    }

    # Microsoft Defender service and Tamper Protection.
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $mp = Get-MpComputerStatus
            Write-Info ('Microsoft Defender: service ' + (Format-Value $mp.AMServiceEnabled) + ', antivirus ' + (Format-Value $mp.AntivirusEnabled) + ', real-time protection ' + (Format-Value $mp.RealTimeProtectionEnabled) + ', Tamper Protection ' + (Format-Value $mp.IsTamperProtected))
        } else {
            Write-Info 'Microsoft Defender: the Defender cmdlets are not available'
        }
    } catch {
        Write-Info ('Microsoft Defender: cannot read the status (' + $_.Exception.Message + ')')
    }

    # Every attack surface reduction rule that is configured, with its action.
    try {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $pref = Get-MpPreference
            $ids = @()
            if ($null -ne $pref.AttackSurfaceReductionRules_Ids) {
                $ids = @($pref.AttackSurfaceReductionRules_Ids)
            }
            $actions = @($pref.AttackSurfaceReductionRules_Actions)
            if ($ids.Count -eq 0) {
                Write-Info 'Attack surface reduction: no rule is configured'
            }
            for ($i = 0; $i -lt $ids.Count; $i++) {
                Write-Info ('Attack surface reduction rule ' + [string]$ids[$i] + ': ' + (Get-AsrActionName $actions[$i]))
            }
        }
    } catch {
        Write-Info ('Attack surface reduction: cannot read the rules (' + $_.Exception.Message + ')')
    }

    # Memory Integrity (HVCI) and Credential Guard.
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
        $running = @($dg.SecurityServicesRunning)
        $configured = @($dg.SecurityServicesConfigured)
        Write-Info ('Memory Integrity (HVCI): running ' + ($running -contains 2) + ', configured ' + ($configured -contains 2))
        Write-Info ('Credential Guard: running ' + ($running -contains 1) + ', configured ' + ($configured -contains 1))
        Write-Info ('Virtualization-based security status: ' + (Format-Value $dg.VirtualizationBasedSecurityStatus) + ' (0 off, 1 configured, 2 running)')
    } catch {
        Write-Info ('Memory Integrity / Credential Guard: cannot read Win32_DeviceGuard (' + $_.Exception.Message + ')')
    }
    try {
        $hv = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
        $cg = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags'
        Write-Info ('Registry: Memory Integrity Enabled = ' + (Format-Value $hv) + ', Credential Guard LsaCfgFlags = ' + (Format-Value $cg))
    } catch {
        Write-Info ('Registry: cannot read the Memory Integrity / Credential Guard values (' + $_.Exception.Message + ')')
    }

    # Exploit Protection (system-wide defaults).
    try {
        if (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue) {
            $mit = Get-ProcessMitigation -System
            Write-Info ('Exploit Protection (system): DEP ' + (Format-Value $mit.DEP.Enable) + ', SEHOP ' + (Format-Value $mit.SEHOP.Enable) + ', ASLR bottom-up ' + (Format-Value $mit.ASLR.BottomUp))
        } else {
            Write-Info 'Exploit Protection: the Get-ProcessMitigation cmdlet is not available'
        }
    } catch {
        Write-Info ('Exploit Protection: cannot read the settings (' + $_.Exception.Message + ')')
    }
    Write-Log ('[DONE] ' + $script:CountOk + ' in effect, ' + $script:CountDiff + ' not in effect')
} elseif ($Mode -eq 'Undo') {
    try {
        if (($script:State.Count -eq 0) -and (Test-Path -LiteralPath $script:StatePath)) {
            Remove-Item -LiteralPath $script:StatePath -Force
            Write-Info 'nothing is left to put back: the state file was removed'
        }
    } catch {
        Write-Log ('[WARN] the empty state file could not be removed: ' + $_.Exception.Message)
    }
    Write-Log '[NOTE] Not undone by this script: optional features that Apply turned off (SMBv1, PowerShell 2.0) stay off; the lines above give the Enable-WindowsOptionalFeature command if you really need them. The SMBv1 server value is never written back as 1.'
    Write-Log '[NOTE] The Security event log keeps its raised size (this script never shrinks it).'
    Write-Log '[NOTE] A setting that was already in the wanted state before Apply was never recorded, so Undo cannot know its history and leaves it alone.'
    Write-Log '[NOTE] Audit policy is put back per subcategory from the recorded auditpol output (English Windows only). The whole earlier policy was also saved once; restore it by hand with: auditpol /restore /file:<that file>'
    Write-Log '[NOTE] UAC and NetBIOS changes take full effect after a restart.'
    Write-Log ('[DONE] ' + $script:CountOk + ' put back, ' + $script:CountSkip + ' skipped, ' + $script:CountWarn + ' warnings')
    if (($script:CountWarn + $script:CountFail) -gt 0) {
        Write-Log '[NOTE] Some items were not put back (see the [WARN] lines above). A record that could not be put back is kept, so running Undo again retries it. The exit code is 1.'
    }
    if (($script:CountWarn + $script:CountFail) -gt 0) { exit 1 }
} else {
    Write-Log ('[DONE] ' + $script:CountOk + ' ok, ' + $script:CountSkip + ' skipped, ' + $script:CountWarn + ' not in effect, ' + $script:CountFail + ' failed')
}
exit 0
