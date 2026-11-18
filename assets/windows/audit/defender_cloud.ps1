
try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $pref = Get-MpPreference
        $bad = @()
        if ([int]$pref.PUAProtection -ne 1) { $bad += 'PUA protection is ' + [int]$pref.PUAProtection + ', wanted 1' }
        if ([int]$pref.MAPSReporting -ne 2) { $bad += 'cloud protection (MAPS) is ' + [int]$pref.MAPSReporting + ', wanted 2' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' '@WHAT@' 'PUA protection and cloud protection are on'
        } else {
            Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
