$enc = New-Object System.Text.UTF8Encoding $true
$files = Get-ChildItem -Path "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\hyperv-attachment\src" -Recurse -Include *.cpp,*.h
foreach ($f in $files) {
    $c = Get-Content -Path $f.FullName -Raw -Encoding UTF8
    [System.IO.File]::WriteAllText($f.FullName, $c, $enc)
    Write-Host "Converted $($f.Name)"
}