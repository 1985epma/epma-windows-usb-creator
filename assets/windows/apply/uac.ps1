
try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $cur = Get-RegDword -Path $key -Name 'EnableLUA'
    if (($null -ne $cur) -and ([int]$cur -eq 0)) {
        Set-RegDword -Path $key -Name 'EnableLUA' -Value 1 | Out-Null
        Write-Result 'OK' '@WHAT@' 'was off, turned on (effective after the next restart)'
    } else {
        Write-Result 'OK' '@WHAT@' 'already on, left unchanged'
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
