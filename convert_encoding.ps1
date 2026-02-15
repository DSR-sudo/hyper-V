$enc = New-Object System.Text.UTF8Encoding $true
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$sourceRoots = @(
    "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\hyperv-attachment\src",
    "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\uefi-boot\src"
)
foreach ($root in $sourceRoots) {
    $files = Get-ChildItem -Path $root -Recurse -Include *.c,*.cpp,*.h
    foreach ($f in $files) {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $start = 0
        while ($start -le ($bytes.Length - 3) -and $bytes[$start] -eq 0xEF -and $bytes[$start+1] -eq 0xBB -and $bytes[$start+2] -eq 0xBF) {
            $start += 3
        }
        if ($start -gt 0) {
            if ($start -ge $bytes.Length) {
                $cleanBytes = [byte[]]@()
            } else {
                $cleanBytes = $bytes[$start..($bytes.Length - 1)]
            }
        } else {
            $cleanBytes = $bytes
        }
        $text = $utf8NoBom.GetString($cleanBytes)
        [System.IO.File]::WriteAllText($f.FullName, $text, $enc)
        Write-Host "Sanitized $($f.Name)"
    }
}
