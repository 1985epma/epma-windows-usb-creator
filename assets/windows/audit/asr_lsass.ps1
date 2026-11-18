
try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $now = Get-AsrAction '@LSASS@'
        if ($now -eq 1) {
            Write-Audit 'OK' '@WHAT@' 'the rule is in Block mode'
        } else {
            Write-Audit 'DIFF' '@WHAT@' ('the rule action is: ' + (Get-AsrActionName $now))
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
