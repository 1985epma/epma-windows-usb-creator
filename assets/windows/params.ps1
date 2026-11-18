[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Audit', 'Undo')]
    [string]$Mode = 'Apply',
    [switch]$DisableLegacyNetwork,
    [string]$LogPath = (Join-Path $env:windir 'Temp\epma-hardening.log')
)
