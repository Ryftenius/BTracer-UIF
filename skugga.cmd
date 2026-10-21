@echo off
setlocal

set "SKUGGA_SCRIPT_DIR=%~dp0"
set "SKUGGA_ROOT=%SKUGGA_SCRIPT_DIR%"
if not exist "%SKUGGA_ROOT%VCXProj\SkuggaRunner.vcxproj" if exist "%SKUGGA_SCRIPT_DIR%SKUGGA\VCXProj\SkuggaRunner.vcxproj" set "SKUGGA_ROOT=%SKUGGA_SCRIPT_DIR%SKUGGA\"
set "SKUGGA_RUNNER="

if defined SKUGGA_CONFIG if exist "%SKUGGA_ROOT%bin\%SKUGGA_CONFIG%\x64\SkuggaRunner.exe" set "SKUGGA_RUNNER=%SKUGGA_ROOT%bin\%SKUGGA_CONFIG%\x64\SkuggaRunner.exe"
if not defined SKUGGA_RUNNER if exist "%SKUGGA_ROOT%bin\Release\x64\SkuggaRunner.exe" set "SKUGGA_RUNNER=%SKUGGA_ROOT%bin\Release\x64\SkuggaRunner.exe"
if not defined SKUGGA_RUNNER if exist "%SKUGGA_ROOT%bin\ReleaseStaged\x64\SkuggaRunner.exe" set "SKUGGA_RUNNER=%SKUGGA_ROOT%bin\ReleaseStaged\x64\SkuggaRunner.exe"
if not defined SKUGGA_RUNNER if exist "%SKUGGA_ROOT%bin\Debug\x64\SkuggaRunner.exe" set "SKUGGA_RUNNER=%SKUGGA_ROOT%bin\Debug\x64\SkuggaRunner.exe"

if not defined SKUGGA_RUNNER (
    echo [skugga] missing SkuggaRunner.exe under "%SKUGGA_ROOT%bin".
    echo [skugga] Build it first from "%SKUGGA_ROOT%" with:
    echo [skugga]   msbuild .\VCXProj\SkuggaRunner.vcxproj /p:Configuration=Release /p:Platform=x64
    exit /b 2
)

"%SKUGGA_RUNNER%" --cli %*
exit /b %ERRORLEVEL%
