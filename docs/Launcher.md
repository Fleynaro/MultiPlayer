# Android/Launcher

`Android/Launcher` is an independent x64 C++20 project. It does not include or
link against the historical `MultiPlayer`, `Injector`, or `GTAV_Loader`
projects. The implementation uses the documented architecture as a reference
and keeps the GTA V build boundary explicit: the game signatures currently
target build 1.41.

## Runtime chain

```text
Launcher.exe
  -> GTAVLauncher.exe (suspended)
     -> Bootstrap.dll
        -> GTA5.exe (suspended)
           -> Client.dll
              -> pattern hooks + Direct3D 11/ImGui overlay
```

`GTA_5_INSTALL_DIR` selects the directory containing `GTAVLauncher.exe`. The
launcher and both DLLs are expected in the same output directory. The launcher
does not run the game during a build or installation step.

`Launcher.exe` embeds a Windows application manifest that requests the
`requireAdministrator` execution level. Windows therefore displays the UAC
prompt automatically when the launcher is started, and the launcher process
always runs elevated after approval. The executable also embeds the project
launcher icon as its application icon.

## Client behavior

- Script execution is filtered using the script name at offset `0xD0`.
- The same allow-list used by the documented multiplayer module remains
  enabled; other listed single-player scripts are suppressed.
- Ped/vehicle startup spawning, fire dispatch, distant fake vehicles, special
  skill, wanted and police update paths are suppressed using build 1.41 byte
  signatures.
- The overlay hooks the Direct3D 11 swap-chain `Present` method and displays
  the process id, renderer, and installed hook count. `F4` toggles the window.
  The UI scales from the game window DPI and framebuffer resolution, enables
  ImGui keyboard navigation, and forwards Win32 mouse/keyboard messages to
  ImGui; while the overlay is open, ImGui draws its own software cursor even
  when the in-game cursor is hidden. Captured messages are blocked from
  reaching the game while the overlay is interacting with them.
- The client embeds CPython, exposes a validated `gta` pybind11 module, and
  loads user scripts from the configured `ScriptsDirectory` (default:
  `runtime/scripts`). Native requests are marshalled to
  the game thread and use handlers captured by the build 1.41 registration
  hook; unavailable handlers fail as Python exceptions.
- Native calls use `hashes_ver141.json` beside `Client.dll` to translate
  static native hashes to build-specific hashes before handler lookup.
- The overlay provides a Python script selector, run/stop controls, and a
  bounded console. Python `print()` output from stdout and stderr is routed to
  the console and to `GtaLauncher.log`. Each `Run script` action starts an independent worker and
  does not block on other running scripts, so long-lived servers and test
  scripts can coexist. `Stop` requests shutdown for all active scripts.
  `scripts/gta.pyi` is the strict typing contract for scripts.
- `gta.invoke_native(hash, arguments)` invokes any registered native without a
  generated binding. `hash` is an unsigned 64-bit native hash and `arguments`
  is a list of up to 32 `bool`, `int`, `float`, `str`, `None`, or `gta.Vector3`
  values. Integers are passed as raw ABI words, floats as IEEE-754 single-
  precision bits, strings as native C-string pointers, and `Vector3` values as
  pointers to three floats. The function returns the first raw 64-bit result
  slot; callers must know the native's argument and result ABI because the
  signature is not available dynamically. `None` and void-native results are
  represented by zero.
- `scripts/agent_server.py` provides a localhost HTTP bridge for external agents.
  It can be started from the overlay or configured for automatic startup; it starts `ThreadingHTTPServer` on a dedicated
  thread at `127.0.0.1:8766`. The API accepts `POST /run?path=script.py` and
  executes the selected script with `runpy.run_path`. The JSON response contains
  `ok`, `path`, `stdout`, `stderr`, and `error`; scripts must be direct `.py`
  children of the configured scripts directory.
  From Windows PowerShell, run a script through the agent server with:

  ```powershell
  Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8766/run?path=test_script.py" | ConvertTo-Json -Depth 5
  ```
- During embedded Python initialization, the launcher registers the active
  CPython prefix and `DLLs` directories with the Windows DLL loader. This is
  required for standard-library extension modules such as `_socket.pyd`.

The renderer hook is installed before game signature scanning so GTA V cannot
create its swap chain while client initialization is still scanning.

## Runtime configuration

`Launcher.ini` is installed beside `Launcher.exe`, `Bootstrap.dll`, and
`Client.dll`. It contains English comments for every available parameter.
`Python/ScriptsDirectory` selects the directory containing `.py` files and may
be absolute or relative to the runtime directory. The built-in default is
`scripts`; `GTA_5_PYTHON_SCRIPT_DIR`, when defined and non-empty, overrides both
the `.ini` value and the default. `Python/SitePackagesDirectory`
controls the additional Python package directory and defaults to
`.venv/Lib/site-packages` when commented out. `Launcher/GameInstallDirectory`
can replace `GTA_5_INSTALL_DIR`; when it is commented out, the environment
variable remains the fallback. `GUI/Scale` overrides automatic DPI and
resolution scaling when greater than zero; `GUI/WindowWidth`,
`GUI/WindowHeight` controls the initial overlay layout. The Python console
  occupies the remaining vertical space and stays attached to the bottom edge.
`Python/AutoStartScripts` is an optional semicolon-separated list of direct `.py`
children of `ScriptsDirectory`. These scripts start automatically after embedded
Python initialization and may run concurrently, which is suitable for long-lived
agent servers. Invalid or missing entries are logged and skipped.
Missing optional values use these defaults and are recorded in `GtaLauncher.log`.

`agent_server.py` locates the loaded `Client.dll` with the Windows module API and
starts the debugpy adapter with `.venv/Scripts/python.exe` beside that DLL. This
is required because the embedded interpreter reports `Launcher.exe` as
`sys.executable`, which cannot execute debugpy's adapter module. Install the
pinned dependency into that runtime virtual environment before starting the
agent server; the scripts directory may be located elsewhere.

Pattern misses are non-fatal and are reflected by the installed hook count.
This avoids terminating the game when Rockstar changes a signature, but a
different game build is not considered supported until its signatures have
been reviewed and updated.

## Build

From a VS Developer PowerShell with `VCPKG_ROOT` set:

```powershell
cmake --preset ninja-msvc
cmake --build build --config Release
cmake --install build --config Release --prefix runtime
```

Run the copy from `runtime`, not from a stale directory containing binaries
from the previous dynamic MinHook build.

For a one-click MSVC build, run `Android/Launcher/build.bat`.
It configures the static vcpkg triplet, builds the project, removes the old
`runtime` directory, and installs a clean runtime bundle there. Before removing
the directory, it enumerates every `GTA5.exe` and `GTAVLauncher.exe` process
and forcibly ends each process tree so loaded runtime DLLs can be replaced. If
Windows denies access, run the script as Administrator or close the game
processes manually.

Dependencies are declared in `Android/Launcher/vcpkg.json` and are provided by
vcpkg: MinHook, pybind11, and ImGui with Win32/DirectX 11 backends. CMake also
requires a shared CPython 3.12 development installation with `Include_libs`
enabled. CPython must not be linked from the static `x64-windows-static`
triplet because extension modules such as `_socket.pyd` require
`python312.dll`. The build script selects the installed CPython development
root and copies its runtime DLL beside `Client.dll`. For the planned Python 3.12
setup, create `runtime/.venv` with `python -m venv runtime/.venv` and install
the pinned dependency from `Android/Launcher/requirements.txt` into that
environment. The client adds `runtime/.venv/Lib/site-packages` to `sys.path`.
The example listens on `127.0.0.1:5679`; use the repository-level
`.vscode/launch.json` to attach.

## Diagnostics and recovery

All launcher, bootstrap, and client failures use English modal diagnostics and
also write the same context to the debugger output and to `GtaLauncher.log`.
The log is appended beside the binary that produced the event, so launcher,
bootstrap, and client events share one file when the three binaries are kept in
the same runtime directory. If that directory is not writable, logging falls
back to `%TEMP%\GtaLauncher.log`. The log includes timestamps, process IDs,
severity, component names, hook and signature results, injection stages, and
renderer initialization events. Game hook diagnostics additionally include
resolved target addresses, MinHook status codes, every native registration
hash/handler pair, native invocation hashes, and the registered-handler count.
Each diagnostic includes a required or recommended recovery action.

`Launcher.exe`, `Bootstrap.dll`, and `Client.dll` install an unhandled exception
handler. A fatal Windows exception or C++ `std::terminate` writes a timestamped
`GtaLauncher-*.dmp` file into a `CrashDumps` directory beside the binary that
installed the handler and appends one short `FATAL` entry to `GtaLauncher.log`.
The dump
contains thread information, unloaded modules, data sections, and indirectly
referenced memory. If dump creation fails, the log records the Windows error;
the crash is still allowed to terminate normally.

Fatal log entries include the decoded exception name, faulting thread, faulting
module and offset, and for access violations the operation and target address.

The crash handler also installs a vectored exception registration that
reasserts the last-chance handler if game code or security software replaces
the process-wide unhandled exception filter, plus C runtime handlers for
invalid parameters and pure virtual calls.
Bootstrap additionally monitors every injected `GTA5.exe` process and records
its exit code in `GtaLauncher.log`; this captures fail-fast and explicit
process termination cases where Windows does not dispatch a catchable exception.

- If `GTA_5_INSTALL_DIR` is missing, set it to the directory that directly
  contains `GTAVLauncher.exe`, then restart `Launcher.exe`.
- If `Bootstrap.dll` or `Client.dll` is missing, build the project and keep all
  three main binaries in the same output directory. MinHook is linked
  statically through the `x64-windows-static` vcpkg triplet, so no separate
  `minhook.x64.dll` is required.
- If process creation or injection fails, approve the launcher's UAC prompt,
  close existing GTA V processes, and disable conflicting overlays/security
  tools. If no prompt appears, rebuild `Launcher.exe` so its embedded manifest
  is up to date.
- If no signatures are found, use the supported GTA V build 1.41 x64 binary.
  A partial signature match is reported as a warning and should not be treated
  as full compatibility.
- If Direct3D or ImGui initialization fails, use Direct3D 11 and ensure the
  vcpkg ImGui backends match the built `Client.dll`.
