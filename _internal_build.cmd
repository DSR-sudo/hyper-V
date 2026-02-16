@echo off
echo [Encoding] Normalizing source files...
powershell -ExecutionPolicy Bypass -File "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\convert_encoding.ps1"
echo [EWDK] Building Solution...
msbuild "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\hyper-reV.sln" /p:Configuration=Release /p:Platform=x64 /t:rebuild
if errorlevel 1 exit /b 1
exit /b 0
