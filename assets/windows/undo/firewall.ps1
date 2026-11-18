
try {
    $r = @()
    $r += Restore-FirewallState
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
