
try {
    $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $todo = @($profiles | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    $changedNote = 'already set'
    if ($todo.Count -gt 0) {
        Save-FirewallState
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
        $changedNote = 'changed on ' + $todo.Count + ' profile(s)'
    }
    # Read the profiles back: "no error" is not the same as "in effect" (a Group Policy or another firewall can win).
    $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    if ($off.Count -eq 0) {
        Write-Result 'OK' '@WHAT@' $changedNote
    } else {
        Write-Result 'WARN' '@WHAT@ not in effect' ('still off or open on ' + $off.Count + ' profile(s); likely reason: Group Policy, another firewall product or the firewall service not ready yet')
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
