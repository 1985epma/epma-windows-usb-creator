
try {
    $r = @()
    $r += Restore-DefenderValue 'PUAProtection'
    $r += Restore-DefenderValue 'MAPSReporting'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' ($_.Exception.Message + ' (Tamper Protection or another antivirus can block this)')
}
