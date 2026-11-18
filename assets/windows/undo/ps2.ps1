
try {
    $notes = @()
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $n = Restore-FeatureState $name
        if ($null -ne $n) { $notes += $n }
    }
    if ($notes.Count -eq 0) {
        Write-Result 'SKIP' '@WHAT@' 'nothing recorded, this script did not change it'
    } else {
        Write-Result 'WARN' '@WHAT@ (optional feature not turned on again)' ($notes -join ' | ')
    }
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
