
try {
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
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
            Write-Result 'WARN' '@WHAT@ not in effect' (($missing -join ', ') + ' still off; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
        } elseif ($changed.Count -eq 0) {
            Write-Result 'OK' '@WHAT@' 'already set'
        } else {
            Write-Result 'OK' '@WHAT@' ('turned on: ' + ($changed -join ', '))
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
