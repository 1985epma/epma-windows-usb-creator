
try {
    $found = $false
    $disabled = @()
    $restart = @()
    $failed = @()
    $fresh = $false
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        # One feature at a time, each in its own try/catch: turning the Root feature off can already turn the child
        # feature off, so the state is read again before the second one, and an error is judged by the state it left.
        try {
            $state = Get-FeatureState $name -Fresh:$fresh
            if ($null -ne $state) {
                $found = $true
                if ($state -eq 'Enabled') {
                    Save-FeatureState $name $state
                    Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart | Out-Null
                    $fresh = $true
                    $after = Get-FeatureState $name -Fresh
                    if (@('DisablePending', 'EnablePending') -contains $after) {
                        $restart += $name
                    } elseif (($after -eq 'Disabled') -or ($after -eq 'DisabledWithPayloadRemoved')) {
                        $disabled += $name
                    } else {
                        throw ('the feature is still ' + (Format-Value $after) + ' after it was turned off')
                    }
                } elseif (@('DisablePending', 'EnablePending') -contains $state) {
                    $restart += $name
                }
            }
        } catch {
            $why = $_.Exception.Message
            $fresh = $true
            $again = $null
            try { $again = Get-FeatureState $name -Fresh } catch { $again = $null }
            if (($again -eq 'Disabled') -or ($again -eq 'DisabledWithPayloadRemoved')) {
                $disabled += $name
            } elseif ($again -eq 'DisablePending') {
                $restart += $name
            } else {
                $failed += ($name + ': ' + $why)
            }
        }
    }
    if ($failed.Count -gt 0) {
        Write-Result 'FAIL' '@WHAT@' ($failed -join ' | ')
    } elseif ($restart.Count -gt 0) {
        Write-Result 'WARN' '@WHAT@ needs a restart' ('change pending for ' + ($restart -join ', ') + '; restart Windows to finish turning the feature off')
    } elseif (-not $found) {
        Write-Result 'SKIP' '@WHAT@' 'feature not present on this Windows build'
    } elseif ($disabled.Count -gt 0) {
        Write-Result 'OK' '@WHAT@' 'feature disabled'
    } else {
        Write-Result 'OK' '@WHAT@' 'already off'
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
