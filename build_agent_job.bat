@echo off
setlocal EnableDelayedExpansion

:: ==================================================================================
:: Build Agent Job Script - Time-Slicing Fix Version
:: ==================================================================================

:: --- Configuration ---
set "PYTHON_EXE=C:\Users\DRS\AppData\Local\Programs\Python\Python313\python.exe"
set "EDK2_PATH=D:\edk2"
set "EWDK_ROOT=D:\Ewdk"

:: --- Project Paths ---
set "PROJECT_ROOT=%~dp0"
set "SOLUTION_FILE=%PROJECT_ROOT%hyper-reV.sln"

:: --- 1. Environment Check ---
echo [Agent] Verifying Environment...
if not exist "%PYTHON_EXE%" ( echo [ERROR] Python missing & goto :Fail )
if not exist "%EDK2_PATH%" ( echo [ERROR] EDK2 missing & goto :Fail )
if not exist "%EWDK_ROOT%\LaunchBuildEnv.cmd" ( echo [ERROR] EWDK missing & goto :Fail )

:: --- 2. Setup EDK2 Env ---
echo [Agent] Setting up EDK2 Variables...
set "WORKSPACE=%EDK2_PATH%"
set "EDK_TOOLS_PATH=%EDK2_PATH%\BaseTools"
set "CONF_PATH=%EDK2_PATH%\Conf"
for %%F in ("%PYTHON_EXE%") do set "PYTHON_DIR=%%~dpF"
set "PATH=%PYTHON_DIR%;%PATH%"

:: --- 3. Create Build Task ---
set "INTERNAL_TASK=%PROJECT_ROOT%_internal_build.cmd"
(
    echo @echo off
    echo echo [EWDK] Building Solution...
    echo msbuild "%SOLUTION_FILE%" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
    echo if errorlevel 1 exit /b 1
    echo exit /b 0
) > "%INTERNAL_TASK%"

:: --- 4. Execute Build ---
echo [Agent] Launching EWDK Build...
call "%EWDK_ROOT%\LaunchBuildEnv.cmd" "%INTERNAL_TASK%"

if %errorlevel% neq 0 (
    echo [Agent] Build FAILED.
    goto :Fail
)

:: --- 5. Verify & Clean ---
del "%INTERNAL_TASK%"
echo [Agent] Verifying Output...
if exist "%PROJECT_ROOT%uefi-boot\uefi-boot.efi" ( echo [OK] uefi-boot.efi ) else ( goto :Fail )
if exist "%PROJECT_ROOT%hyperv-attachment\hyperv-attachment.dll" ( echo [OK] hyperv-attachment.dll ) else ( goto :Fail )

echo [Agent] BUILD SUCCESSFUL.
goto :EOF

:Fail
if exist "%INTERNAL_TASK%" del "%INTERNAL_TASK%"
echo [Agent] BUILD FAILED.
exit /b 1
