
try {
    $r = @()
    $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
