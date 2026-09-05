@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Build the standalone GTA launcher and install a clean runtime bundle.
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "BUILD_DIR=%SCRIPT_DIR%\build"
set "RUNTIME_DIR=%SCRIPT_DIR%\runtime"

rem Use the caller-provided vcpkg installation or the standard local installation.
if not defined VCPKG_ROOT if exist "C:\dev\vcpkg\scripts\buildsystems\vcpkg.cmake" set "VCPKG_ROOT=C:\dev\vcpkg"
if not defined VCPKG_ROOT (
    echo ERROR: VCPKG_ROOT is not set.
    echo Set VCPKG_ROOT to the vcpkg directory and run this script again.
    exit /b 1
)
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
    echo ERROR: The vcpkg toolchain was not found at "%VCPKG_ROOT%".
    echo Install vcpkg or correct VCPKG_ROOT.
    exit /b 1
)

rem Initialize the Microsoft x64 compiler environment when cl.exe is unavailable.
if not defined DevEnvDir (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" for /f "usebackq delims=" %%V in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%V"
    if defined VS_INSTALL set "VS_DEV_CMD=!VS_INSTALL!\Common7\Tools\VsDevCmd.bat"
    if not defined VS_DEV_CMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VS_DEV_CMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    if not defined VS_DEV_CMD if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" set "VS_DEV_CMD=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
    if not defined VS_DEV_CMD (
        echo ERROR: No Visual Studio installation with the MSVC x64 workload was found.
        echo Install the Desktop development with C++ workload and Windows SDK.
        exit /b 1
    )
    call "!VS_DEV_CMD!" -arch=x64 -host_arch=x64
    if errorlevel 1 (
        echo ERROR: Visual Studio compiler environment initialization failed.
        exit /b 1
    )
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: cmake was not found in PATH.
    echo Install CMake and Ninja, then run this script from a Developer Command Prompt.
    exit /b 1
)
where ninja >nul 2>&1
if errorlevel 1 (
    echo ERROR: ninja was not found in PATH.
    echo Install Ninja and run this script from a Developer Command Prompt.
    exit /b 1
)

echo Configuring the x64 static-vcpkg build...
rem Remove stale CMake cache files so the script cannot reuse another compiler or triplet.
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
where py >nul 2>&1
if errorlevel 1 (
    echo ERROR: CPython 3.12 launcher was not found.
    echo Install CPython 3.12 with the Include_libs development files enabled.
    exit /b 1
)
for /f "usebackq delims=" %%P in (`py -3.12 -c "import sys; print(sys.prefix)"`) do set "PYTHON_ROOT=%%P"
if not exist "!PYTHON_ROOT!\include\Python.h" (
    echo ERROR: CPython development headers were not found in "!PYTHON_ROOT!".
    echo Repair CPython 3.12 and enable Include_libs.
    exit /b 1
)
if not exist "!PYTHON_ROOT!\libs\python312.lib" (
    echo ERROR: CPython shared import library was not found in "!PYTHON_ROOT!\libs".
    echo Repair CPython 3.12 and enable Include_libs.
    exit /b 1
)
cmake -S "%SCRIPT_DIR%" -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_CXX_COMPILER=cl -DGTA_PYTHON_ROOT="!PYTHON_ROOT!"
if errorlevel 1 (
    echo ERROR: CMake configuration failed.
    exit /b 1
)

echo Building Launcher.exe, Bootstrap.dll, and Client.dll...
cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 (
    echo ERROR: The C++ build failed.
    exit /b 1
)

rem GTA V keeps the injected DLLs loaded until both the game and launcher exit.
rem Use Win32_Process.Terminate instead of taskkill because GTA can expose a
rem stale PID to taskkill while the process is still holding runtime DLLs.
echo Closing GTA V processes that may lock runtime DLLs...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$names = @('GTA5.exe', 'GTAVLauncher.exe'); $processes = @(Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name } | Sort-Object @{Expression = { if ($_.Name -eq 'GTAVLauncher.exe') { 0 } else { 1 } }}); foreach ($process in $processes) { Write-Host ('Closing ' + $process.Name + ' with PID ' + $process.ProcessId + '...'); try { $result = Invoke-CimMethod -InputObject $process -MethodName Terminate -ErrorAction Stop; if ($result.ReturnValue -ne 0) { Write-Error ('Win32_Process.Terminate failed for PID ' + $process.ProcessId + ' with code ' + $result.ReturnValue); exit 1 } } catch { Write-Error ('Could not close PID ' + $process.ProcessId + ': ' + $_.Exception.Message); exit 1 } }; Start-Sleep -Milliseconds 500; $remaining = @(Get-Process -Name 'GTA5', 'GTAVLauncher' -ErrorAction SilentlyContinue); if ($remaining.Count -gt 0) { $remaining | ForEach-Object { Write-Error ('Process is still running: ' + $_.ProcessName + ' with PID ' + $_.Id) }; exit 1 }"
if errorlevel 1 (
    echo ERROR: GTA V processes could not be closed.
    echo Run this script as Administrator and close any external process supervisors.
    exit /b 1
)

if exist "%RUNTIME_DIR%" rmdir /s /q "%RUNTIME_DIR%"
echo Installing the clean runtime bundle to "%RUNTIME_DIR%"...
cmake --install "%BUILD_DIR%" --config Release --prefix "%RUNTIME_DIR%"
if errorlevel 1 (
    echo ERROR: Runtime installation failed.
    exit /b 1
)

if not exist "%RUNTIME_DIR%\.venv\Scripts\python.exe" (
    where py >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Python launcher was not found; create runtime\.venv with CPython 3.12 manually.
    ) else (
        py -3.12 -m venv "%RUNTIME_DIR%\.venv"
        if errorlevel 1 echo WARNING: Could not create runtime\.venv with CPython 3.12.
    )
)
if exist "%RUNTIME_DIR%\.venv\Scripts\python.exe" (
    "%RUNTIME_DIR%\.venv\Scripts\python.exe" -m pip install -r "%SCRIPT_DIR%\requirements.txt"
    if errorlevel 1 echo WARNING: debugpy installation failed; install requirements.txt manually.
)

if not exist "%RUNTIME_DIR%\Launcher.exe" goto :missing_output
if not exist "%RUNTIME_DIR%\Bootstrap.dll" goto :missing_output
if not exist "%RUNTIME_DIR%\Client.dll" goto :missing_output

echo.
echo Build completed successfully.
echo Runtime files are in:
echo   %RUNTIME_DIR%
exit /b 0

:missing_output
echo ERROR: One or more runtime files are missing after installation.
echo Expected Launcher.exe, Bootstrap.dll, and Client.dll in "%RUNTIME_DIR%".
exit /b 1
