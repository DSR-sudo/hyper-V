@echo off
setlocal enabledelayedexpansion
set ROOT=D:\Hyper
set MSBUILD_EXE=
for /f "delims=" %%F in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" 2^>nul') do set MSBUILD_EXE=%%F
if not defined MSBUILD_EXE (
  for /f "delims=" %%F in ('dir /b /s "C:\Program Files (x86)\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" 2^>nul') do set MSBUILD_EXE=%%F
)
if not defined MSBUILD_EXE (
  for /f "delims=" %%F in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\*\*\MSBuild\*\Bin\MSBuild.exe" 2^>nul') do set MSBUILD_EXE=%%F
)
if not defined MSBUILD_EXE (
  for /f "delims=" %%F in ('dir /b /s "C:\Program Files (x86)\Microsoft Visual Studio\*\*\MSBuild\*\Bin\MSBuild.exe" 2^>nul') do set MSBUILD_EXE=%%F
)
if not defined MSBUILD_EXE (
  echo MSBuild not found
  exit /b 1
)
set TARGET=
for /r "%ROOT%" %%F in (*.sln) do (
  if not defined TARGET set TARGET=%%F
)
if not defined TARGET (
  for /r "%ROOT%" %%F in (*.vcxproj) do (
    if not defined TARGET set TARGET=%%F
  )
)
if not defined TARGET (
  echo No solution or project found
  exit /b 2
)
echo MSBUILD=%MSBUILD_EXE%
echo TARGET=%TARGET%
"%MSBUILD_EXE%" "%TARGET%" /m /p:Configuration=Release /p:Platform=x64
set EXIT_CODE=%ERRORLEVEL%
if "%EXIT_CODE%"=="0" (
  echo BUILD SUCCESSFUL
)
exit /b %EXIT_CODE%
