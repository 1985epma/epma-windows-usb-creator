
try {
    $r = @()
    $r += Restore-AsrRule '@LSASS@'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
