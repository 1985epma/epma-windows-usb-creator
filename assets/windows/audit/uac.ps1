
try {
    $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    if (($null -ne $cur) -and ([int]$cur -eq 0)) {
        Write-Audit 'DIFF' '@WHAT@' 'EnableLUA is 0, so User Account Control is off'
    } else {
        Write-Audit 'OK' '@WHAT@' ('EnableLUA is ' + (Format-Value $cur) + ' (not 0)')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
