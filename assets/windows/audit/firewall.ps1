
try {
    $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    if ($off.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'all three profiles are on with inbound blocked'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ('off or open on ' + $off.Count + ' of ' + $after.Count + ' profile(s): ' + (($off | ForEach-Object { [string]$_.Name }) -join ', '))
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
