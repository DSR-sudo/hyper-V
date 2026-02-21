@echo off

msbuild D:\RWbase\RWbase\RWbase.slnx ^
 /p:Configuration=Release ^
 /p:Platform="x64" ^
 /p:CLToolAdditionalOptions="/d2EnforceFunctionLevelLinking" ^
 /t:RWbase:rebuild