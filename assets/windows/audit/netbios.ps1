
try {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $names = @()
    if (Test-Path -LiteralPath $base) {
        $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
    }
    if ($names.Count -eq 0) {
        Write-Audit 'NA' '@WHAT@' 'no network interfaces found in the NetBT settings'
    } else {
        $on = @()
        foreach ($n in $names) {
            $cur = Get-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions'
            if (($null -eq $cur) -or ([int]$cur -ne 2)) { $on += $n }
        }
        if ($on.Count -eq 0) {
            Write-Audit 'OK' '@WHAT@' ('NetBIOS over TCP/IP is off on all ' + $names.Count + ' interfaces')
        } else {
            Write-Audit 'DIFF' '@WHAT@' ('' + $on.Count + ' of ' + $names.Count + ' interfaces still use NetBIOS over TCP/IP') -OptIn $true
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
