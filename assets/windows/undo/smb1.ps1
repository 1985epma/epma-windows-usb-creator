
try {
    $r = @()
    $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    Write-UndoSummary '@WHAT@' $r
    # An optional feature that was turned off is NOT turned on again here: that would bring SMBv1 back.
    $note = Restore-FeatureState 'SMB1Protocol'
    if ($null -ne $note) { Write-Result 'WARN' '@WHAT@ (optional feature not turned on again)' $note }
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
