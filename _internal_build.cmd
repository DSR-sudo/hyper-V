@echo off
echo [EWDK] Building Solution...
msbuild "D:\Hyper\hyper-reV.sln" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
if errorlevel 1 exit /b 1
exit /b 0
