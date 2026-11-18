
try {
    $r = @()
    foreach ($k in @($script:State.Keys)) {
        # The key names come from the state file, so each one must match the NetBT interface pattern; the value name is
        # a constant. Nothing else in the file decides what is touched (records that do not match are reported).
        if ($k -match '^reg\|(.+)\|NetbiosOptions$') {
            $ifaceKey = $Matches[1]
            if ($ifaceKey -match $script:NetbtPattern) {
                $r += Restore-RegValue -Path $ifaceKey -Name 'NetbiosOptions'
            }
        }
    }
    if ($r.Count -eq 0) { $r += 'no record' }
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
