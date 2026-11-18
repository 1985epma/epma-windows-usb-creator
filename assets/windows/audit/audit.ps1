
try {
    $items = @(
@AUDIT_ITEMS@
    )
    $bad = @()
    $unknown = 0
    foreach ($item in $items) {
        $cur = Get-AuditSetting $item[0]
        if (-not $cur.known) {
            $unknown++
        } else {
            $satisfied = ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
            if (-not $satisfied) { $bad += $item[1] + ' is: ' + $cur.raw }
        }
    }
    $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
    if ($oldBytes -lt 134217728) { $bad += 'Security log size is ' + [math]::Round($oldBytes / 1MB) + ' MiB, wanted 128 MiB or more' }
    if ($bad.Count -gt 0) {
        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
    } elseif ($unknown -gt 0) {
        Write-Audit 'NA' '@WHAT@' ('the auditpol output of ' + $unknown + ' subcategories could not be read (a non-English Windows prints other words)')
    } else {
        Write-Audit 'OK' '@WHAT@' ('all ' + $items.Count + ' subcategories are set; Security log is ' + [math]::Round($oldBytes / 1MB) + ' MiB')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
