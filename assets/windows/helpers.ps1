
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
$script:StateDir = Join-Path $env:ProgramData '@STATE_DIR@'
$script:StatePath = Join-Path $script:StateDir '@STATE_FILE@'
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
$script:KnownReg = @KNOWN_REG@
$script:KnownAsr = @KNOWN_ASR@
$script:KnownAudit = @KNOWN_AUDIT@
$script:KnownFeatures = @KNOWN_FEATURES@
$script:KnownMp = @KNOWN_MP@
$script:NetbtPattern = '@NETBT_REGEX@'

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
