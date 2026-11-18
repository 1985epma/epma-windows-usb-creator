try {
    $r = @()
    foreach ($id in @(
@ASR_IDS@
    )) {
        $r += Restore-AsrRule $id
    }
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
