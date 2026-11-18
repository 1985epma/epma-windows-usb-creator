
param([string]$Iso)
$before = Get-DiskImage -ImagePath $Iso
$was = 0
if ($before.Attached) { $was = 1 } else { $null = Mount-DiskImage -ImagePath $Iso -StorageType ISO -Access ReadOnly }
$letter = ''
for ($i = 0; $i -lt 30 -and $letter -eq ''; $i++) {
  $vol = Get-DiskImage -ImagePath $Iso | Get-Volume -ErrorAction SilentlyContinue
  if ($vol -and $vol.DriveLetter) { $letter = [string]$vol.DriveLetter } else { Start-Sleep -Seconds 1 }
}
if ($letter -eq '') { throw 'The ISO was mounted but Windows gave it no drive letter.' }
Write-Output ('EPMA_ISO ' + $letter + ' ' + $was)
