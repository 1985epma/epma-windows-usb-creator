
try {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $ruleId = '@LSASS@'
        $r = Set-AsrRule -Id $ruleId -Action 'Enabled'
        $now = Get-AsrAction $ruleId
        if ($now -eq 1) {
            Write-Result 'OK' '@WHAT@' $r
        } else {
            Write-Result 'WARN' '@WHAT@ not in effect' 'rule is not in Block mode; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet'
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
