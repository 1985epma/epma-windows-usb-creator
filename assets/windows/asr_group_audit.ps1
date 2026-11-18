try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $rules = @(
@ASR_IDS@
        )
        $off = @()
        foreach ($id in $rules) {
            $now = Get-AsrAction $id
            if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) { $off += $id + ' (' + (Get-AsrActionName $now) + ')' }
        }
        if ($off.Count -eq 0) {
            Write-Audit 'OK' '@WHAT@' ('all ' + $rules.Count + ' rules are in Audit mode or stricter')
        } else {
            Write-Audit 'DIFF' '@WHAT@' ('' + $off.Count + ' of ' + $rules.Count + ' rules not active: ' + ($off -join ', '))
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
