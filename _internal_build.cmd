@echo off
echo [EWDK] Building Solution...
msbuild "C:\Users\DRS\source\repos\DSR-sudo\hyper-V\hyper-reV.sln" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
if errorlevel 1 exit /b 1
exit /b 0
