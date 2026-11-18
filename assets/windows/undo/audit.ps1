
try {
    $r = @()
    foreach ($guid in @(
@AUDIT_GUIDS@
    )) {
        # Restore-AuditSubcategory never throws: it logs [WARN] could not be restored, keeps the record and returns 'not restored'.
        $r += Restore-AuditSubcategory $guid
    }
    $sizeNote = Restore-EventLogState
    if ($null -ne $sizeNote) { $r += $sizeNote }
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
