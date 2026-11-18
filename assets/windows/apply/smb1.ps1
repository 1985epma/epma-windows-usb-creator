
try {
    $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0
    $note = 'server side already off'
    if ($c1) { $note = 'server side turned off' }
    $restart = $false
    $state = Get-FeatureState 'SMB1Protocol'
    if ($null -eq $state) {
        $note = $note + '; optional feature not present'
    } elseif ($state -eq 'Enabled') {
        Save-FeatureState 'SMB1Protocol' $state
        Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
        # Read the state again: with -NoRestart it often reads DisablePending until the next restart.
        $after = Get-FeatureState 'SMB1Protocol' -Fresh
        if (@('DisablePending', 'EnablePending') -contains $after) {
            $restart = $true
            $note = $note + '; optional feature disabled but a restart is needed to finish it'
        } elseif (($after -eq 'Disabled') -or ($after -eq 'DisabledWithPayloadRemoved')) {
            $note = $note + '; optional feature disabled'
        } else {
            throw ('the optional feature SMB1Protocol is still ' + (Format-Value $after) + ' after it was turned off')
        }
    } elseif (@('DisablePending', 'EnablePending') -contains $state) {
        $restart = $true
        $note = $note + '; optional feature has a change pending, a restart is needed'
    } else {
        $note = $note + '; optional feature already off'
    }
    if ($restart) {
        Write-Result 'WARN' '@WHAT@ needs a restart' $note
    } else {
        Write-Result 'OK' '@WHAT@' $note
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
