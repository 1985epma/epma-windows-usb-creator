
param([string]$Iso)
$null = Dismount-DiskImage -ImagePath $Iso -ErrorAction SilentlyContinue
