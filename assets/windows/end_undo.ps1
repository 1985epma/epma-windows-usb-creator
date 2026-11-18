
try {
    if (($script:State.Count -eq 0) -and (Test-Path -LiteralPath $script:StatePath)) {
        Remove-Item -LiteralPath $script:StatePath -Force
        Write-Info 'nothing is left to put back: the state file was removed'
    }
} catch {
    Write-Log ('[WARN] the empty state file could not be removed: ' + $_.Exception.Message)
}
Write-Log '[NOTE] Not undone by this script: optional features that Apply turned off (SMBv1, PowerShell 2.0) stay off; the lines above give the Enable-WindowsOptionalFeature command if you really need them. The SMBv1 server value is never written back as 1.'
Write-Log '[NOTE] The Security event log keeps its raised size (this script never shrinks it).'
Write-Log '[NOTE] A setting that was already in the wanted state before Apply was never recorded, so Undo cannot know its history and leaves it alone.'
Write-Log '[NOTE] Audit policy is put back per subcategory from the recorded auditpol output (English Windows only). The whole earlier policy was also saved once; restore it by hand with: auditpol /restore /file:<that file>'
Write-Log '[NOTE] UAC and NetBIOS changes take full effect after a restart.'
Write-Log ('[DONE] ' + $script:CountOk + ' put back, ' + $script:CountSkip + ' skipped, ' + $script:CountWarn + ' warnings')
if (($script:CountWarn + $script:CountFail) -gt 0) {
    Write-Log '[NOTE] Some items were not put back (see the [WARN] lines above). A record that could not be put back is kept, so running Undo again retries it. The exit code is 1.'
}
if (($script:CountWarn + $script:CountFail) -gt 0) { exit 1 }
