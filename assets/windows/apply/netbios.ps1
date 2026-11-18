
try {
    if (-not $DisableLegacyNetwork) {
        Write-Result 'SKIP' '@WHAT@' 'opt-in, not requested (run with -DisableLegacyNetwork)'
    } else {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        $names = @()
        if (Test-Path -LiteralPath $base) {
            $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
        }
        if ($names.Count -eq 0) {
            Write-Result 'SKIP' '@WHAT@' 'no network interfaces found in the NetBT settings'
        } else {
            # NetbiosOptions: 0 = use the DHCP setting, 1 = on, 2 = off. Interfaces added later keep their default.
            $changed = 0
            foreach ($n in $names) {
                if (Set-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions' -Value 2) { $changed++ }
            }
            Write-Result 'OK' '@WHAT@' ('' + $changed + ' of ' + $names.Count + ' interfaces changed, the others were already set; effective after the adapters reconnect or after a restart')
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
