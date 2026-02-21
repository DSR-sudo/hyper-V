@echo off
echo [!] Setting up EWDK environment...
call "D:\Ewdk\BuildEnv\SetupBuildEnv.cmd" amd64

echo [!] Applying custom SDK paths...
SET "WindowsSdkDir=D:\Ewdk\Program Files\Windows Kits\10\"
SET "INCLUDE=%WindowsSdkDir%Include\10.0.26100.0\shared;%INCLUDE%"
SET "INCLUDE=%WindowsSdkDir%Include\10.0.26100.0\km;%INCLUDE%"
SET "INCLUDE=%WindowsSdkDir%Include\10.0.26100.0\ucrt;%INCLUDE%"
echo [!] Custom SDK paths have been force-exported.

echo [!] Starting RWbase build using user provided script...
call "c:\Users\DRS\source\repos\DSR-sudo\hyper-V\rwbasecl.bat"

if errorlevel 1 (
    echo [!] RWbase Build FAILED!
    exit /b 1
)
echo [!] RWbase Build SUCCEEDED!
exit /b 0
