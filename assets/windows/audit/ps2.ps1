
try {
    $found = $false
    $on = @()
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $state = Get-FeatureState $name
        if ($null -ne $state) {
            $found = $true
            if ($state -eq 'Enabled') { $on += $name }
            elseif (@('DisablePending', 'EnablePending') -contains $state) { $on += ($name + ' (' + $state + ', a restart is needed)') }
        }
    }
    if (-not $found) {
        Write-Audit 'NA' '@WHAT@' 'feature not present on this Windows build'
    } elseif ($on.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'the feature is off'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ('still enabled: ' + ($on -join ', '))
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
