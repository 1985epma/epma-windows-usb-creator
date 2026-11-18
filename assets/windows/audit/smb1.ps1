
try {
    $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    $state = Get-FeatureState 'SMB1Protocol'
    $bad = @()
    if (($null -eq $cur) -or ([int]$cur -ne 0)) { $bad += 'SMB1 server value is ' + (Format-Value $cur) + ', wanted 0' }
    if ($state -eq 'Enabled') { $bad += 'optional feature SMB1Protocol is Enabled' }
    elseif (@('DisablePending', 'EnablePending') -contains $state) { $bad += 'optional feature SMB1Protocol is ' + $state + ', a restart is needed' }
    if ($bad.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'SMB1 server value is 0 and the optional feature is off or not present'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
