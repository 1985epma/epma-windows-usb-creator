
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
