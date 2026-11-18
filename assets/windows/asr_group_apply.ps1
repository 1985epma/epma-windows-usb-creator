try {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $rules = @(
@ASR_IDS@
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
            Write-Result 'WARN' '@WHAT@ not in effect' ('' + $missing + ' of ' + $rules.Count + ' rules are not active; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
        } else {
            Write-Result 'OK' '@WHAT@' ('' + $applied + ' of ' + $rules.Count + ' rules changed, the others were already set')
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
