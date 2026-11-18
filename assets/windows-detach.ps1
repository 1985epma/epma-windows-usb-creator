
param([int]$Number, [int]$Reattach)
$ok = $true
try { Update-Disk -Number $Number -ErrorAction SilentlyContinue } catch { }
$parts = @(Get-Partition -DiskNumber $Number -ErrorAction SilentlyContinue)
foreach ($p in $parts) {
  if ($p.DriveLetter) {
    $l = [string]$p.DriveLetter
    try { Write-VolumeCache -DriveLetter $l -ErrorAction SilentlyContinue } catch { }
    try { Remove-PartitionAccessPath -DiskNumber $Number -PartitionNumber $p.PartitionNumber -AccessPath ($l + ':\') -ErrorAction Stop }
    catch { $ok = $false }
  }
}
if ($Reattach -eq 1) {
  Start-Sleep -Milliseconds 500
  $first = $parts | Where-Object { $_.Type -ne 'Reserved' } | Select-Object -First 1
  Add-PartitionAccessPath -DiskNumber $Number -PartitionNumber $first.PartitionNumber -AssignDriveLetter
  $first = Get-Partition -DiskNumber $Number -PartitionNumber $first.PartitionNumber
  Write-Output ('EPMA_VOLUME ' + $first.DriveLetter + ' ' + $first.PartitionNumber)
} elseif ($ok) { Write-Output 'EJECTED' } else { Write-Output 'NOT_EJECTED' }
