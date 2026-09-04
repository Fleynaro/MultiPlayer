cmake_minimum_required(VERSION 3.25)
project(GtaLauncher LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "GtaLauncher requires a 64-bit Windows build")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(minhook CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
set(PYBIND11_FINDPYTHON ON)
find_package(Python3 COMPONENTS Interpreter Development.Embed REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

add_library(LauncherCommon INTERFACE)
target_include_directories(LauncherCommon INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(LauncherCommon INTERFACE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(LauncherCommon INTERFACE minhook::minhook)

add_executable(Launcher WIN32 src/launcher/main.cpp src/common/remote_library.cpp src/common/diagnostics.cpp
    src/common/config.cpp)
target_link_libraries(Launcher PRIVATE LauncherCommon)

add_library(Bootstrap SHARED src/bootstrap/dllmain.cpp src/common/remote_library.cpp src/common/diagnostics.cpp)
target_link_libraries(Bootstrap PRIVATE LauncherCommon)
set_target_properties(Bootstrap PROPERTIES OUTPUT_NAME "Bootstrap")

add_library(Client SHARED src/client/dllmain.cpp src/client/pattern_scanner.cpp src/client/game_hooks.cpp src/client/d3d11_overlay.cpp
    src/client/python_runtime.cpp src/common/diagnostics.cpp src/common/config.cpp)
target_link_libraries(Client PRIVATE LauncherCommon d3d11 dxgi)
target_link_libraries(Client PRIVATE imgui::imgui)
target_link_libraries(Client PRIVATE pybind11::embed Python3::Python)
target_compile_definitions(Client PRIVATE PY_SSIZE_T_CLEAN)
set_target_properties(Client PROPERTIES OUTPUT_NAME "Client")

if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc /guard:cf)
    add_link_options(/guard:cf)
endif()

install(TARGETS Launcher Bootstrap Client RUNTIME DESTINATION . LIBRARY DESTINATION .)
install(DIRECTORY scripts/ DESTINATION scripts PATTERN "__pycache__" EXCLUDE)
install(FILES Launcher.ini DESTINATION .)
