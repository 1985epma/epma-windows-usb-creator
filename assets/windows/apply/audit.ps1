
try {
    $items = @(
@AUDIT_ITEMS@
    )
    $bad = 0
    $changed = 0
    $backedUp = $false
    foreach ($item in $items) {
        $cur = Get-AuditSetting $item[0]
        # Already enough (or stricter) is left alone; an unreadable setting is set again.
        $satisfied = $cur.known -and ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
        if (-not $satisfied) {
            try {
                if (-not $backedUp) {
                    Save-AuditBackup
                    $backedUp = $true
                }
                Set-AuditSubcategory $item[0] $item[2] $item[3]
                $changed++
            } catch {
                $bad++
                Write-Result 'FAIL' ('Audit subcategory ' + $item[1] + ' ' + $item[0]) ($_.Exception.Message + ' List valid GUIDs with: auditpol /list /subcategory:* /v')
            }
        }
    }
    # The Security log wraps quickly with these events, so raise its maximum size to 128 MiB. Only ever raised.
    $wantBytes = 134217728
    $sizeOk = $true
    $sizeNote = ''
    try {
        $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
        if ($oldBytes -ge $wantBytes) {
            $sizeNote = 'Security log size left at ' + [math]::Round($oldBytes / 1MB) + ' MiB (already 128 MiB or more)'
        } else {
            Save-EventLogState $oldBytes
            & wevtutil.exe sl Security ('/ms:' + $wantBytes) | Out-Null
            $newBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
            if ($newBytes -ge $wantBytes) {
                $sizeNote = 'Security log size raised from ' + [math]::Round($oldBytes / 1MB) + ' MiB to ' + [math]::Round($newBytes / 1MB) + ' MiB'
            } else {
                $sizeOk = $false
                $sizeNote = 'Security log size is still ' + [math]::Round($newBytes / 1MB) + ' MiB (was ' + [math]::Round($oldBytes / 1MB) + ' MiB); a Group Policy may control it'
            }
        }
    } catch {
        $sizeOk = $false
        $sizeNote = 'could not raise the Security log size: ' + $_.Exception.Message
    }
    if (($bad -gt 0) -or (-not $sizeOk)) {
        Write-Result 'WARN' '@WHAT@ not fully in effect' ('' + $bad + ' of ' + $items.Count + ' subcategories rejected; ' + $sizeNote)
    } else {
        Write-Result 'OK' '@WHAT@' ('' + $items.Count + ' subcategories in effect (' + $changed + ' changed); ' + $sizeNote)
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
