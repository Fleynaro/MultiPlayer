#include "client/python_runtime.h"

#include "client/game_hooks.h"
#include "common/config.h"
#include "common/diagnostics.h"

#include <Python.h>
#include <Windows.h>
#include <algorithm>
#include <bit>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <future>
#include <mutex>
#include <pybind11/embed.h>
#include <pybind11/pybind11.h>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace py = pybind11;

namespace client::python {
namespace {

struct Vec3 {
    float x;
    float y;
    float z;
};

struct NativeRequest {
    std::string operation;
    std::vector<std::uint64_t> arguments;
    std::promise<std::vector<std::uint64_t>> completion;
};

std::mutex state_mutex;
std::mutex request_mutex;
std::queue<std::unique_ptr<NativeRequest>> requests;
std::vector<std::string> output;
std::filesystem::path scripts_directory;
std::string current_script_name;
std::thread worker;
std::atomic_bool runtime_running = false;
std::atomic_bool stop_requested = false;
std::once_flag python_once;

std::wstring wide_from_utf8(const std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int length =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) {
        return L"<UTF-8 conversion failed>";
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(),
                        length);
    return result;
}

std::uint64_t float_bits(const float value) {
    return static_cast<std::uint64_t>(std::bit_cast<std::uint32_t>(value));
}

float bits_float(const std::uint64_t value) {
    return std::bit_cast<float>(static_cast<std::uint32_t>(value));
}

void append_console(std::string line) {
    launcher::diagnostics::log(L"INFO", L"Python", wide_from_utf8(line));
    std::lock_guard lock(state_mutex);
    output.push_back(std::move(line));
    if (output.size() > 500) {
        output.erase(output.begin(), output.begin() + 100);
    }
}

std::vector<std::uint64_t> call_game(std::string operation, std::vector<std::uint64_t> arguments) {
    if (!runtime_running) {
        throw std::runtime_error("Python runtime is not running");
    }
    auto request = std::make_unique<NativeRequest>();
    request->operation = std::move(operation);
    request->arguments = std::move(arguments);
    auto future = request->completion.get_future();
    {
        std::lock_guard lock(request_mutex);
        requests.push(std::move(request));
    }
    return future.get();
}

void validate_entity(int entity) {
    if (entity <= 0 || entity > 0x7FFFFFFF) {
        throw std::invalid_argument("entity handle must be a positive 32-bit value");
    }
}

void validate_coordinate(float value, const char* name) {
    if (!std::isfinite(value) || value < -100000.0F || value > 100000.0F) {
        throw std::invalid_argument(std::string(name) + " must be finite and within GTA world limits");
    }
}

void validate_model_hash(const std::uint32_t hash) {
    if (hash == 0) {
        throw std::invalid_argument("model hash must not be zero");
    }
}

PYBIND11_EMBEDDED_MODULE(gta, module) {
    module.doc() = "Validated GTA V native bridge";
    py::class_<Vec3>(module, "Vector3")
        .def(py::init<float, float, float>())
        .def_readwrite("x", &Vec3::x)
        .def_readwrite("y", &Vec3::y)
        .def_readwrite("z", &Vec3::z);
    module.def("log", [](const std::string& message) {
        if (message.size() > 4096) {
            throw std::invalid_argument("log message is limited to 4096 characters");
        }
        append_console("[script] " + message);
    });
    module.def("wait", [](const int milliseconds) {
        if (milliseconds < 0 || milliseconds > 600000) {
            throw std::invalid_argument("wait milliseconds must be between 0 and 600000");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    });
    auto player = module.def_submodule("player", "PLAYER natives");
    player.def("ped", []() -> int { return static_cast<int>(call_game("PLAYER_GET_PED", {0}).at(0)); });
    auto entity_module = module.def_submodule("entity", "ENTITY natives");
    entity_module.def("exists", [](const int entity) {
        validate_entity(entity);
        return call_game("ENTITY_EXISTS", {static_cast<std::uint64_t>(entity)}).at(0) != 0;
    });
    entity_module.def("health", [](const int entity) -> int {
        validate_entity(entity);
        return static_cast<int>(call_game("ENTITY_HEALTH", {static_cast<std::uint64_t>(entity)}).at(0));
    });
    entity_module.def("coords", [](const int entity) {
        validate_entity(entity);
        const auto result = call_game("ENTITY_COORDS", {static_cast<std::uint64_t>(entity)});
        if (result.size() != 3) {
            throw std::runtime_error("native returned an invalid coordinate result");
        }
        return Vec3{bits_float(result[0]), bits_float(result[1]), bits_float(result[2])};
    });
    entity_module.def("set_coords", [](const int entity, const Vec3 coordinates) {
        validate_entity(entity);
        validate_coordinate(coordinates.x, "x");
        validate_coordinate(coordinates.y, "y");
        validate_coordinate(coordinates.z, "z");
        call_game("ENTITY_SET_COORDS", {static_cast<std::uint64_t>(entity), float_bits(coordinates.x),
                                        float_bits(coordinates.y), float_bits(coordinates.z), 0, 0, 0, 1});
    });
    auto ped = module.def_submodule("ped", "PED natives");
    ped.def(
        "create",
        [](const int ped_type, const std::uint32_t model_hash, const Vec3 coordinates, const float heading,
           const bool is_network, const bool this_script_check) {
            if (ped_type < 0 || ped_type > 32) {
                throw std::invalid_argument("ped type must be between 0 and 32");
            }
            validate_model_hash(model_hash);
            validate_coordinate(coordinates.x, "x");
            validate_coordinate(coordinates.y, "y");
            validate_coordinate(coordinates.z, "z");
            validate_coordinate(heading, "heading");
            return static_cast<int>(
                call_game("PED_CREATE", {static_cast<std::uint64_t>(ped_type), model_hash, float_bits(coordinates.x),
                                         float_bits(coordinates.y), float_bits(coordinates.z), float_bits(heading),
                                         is_network ? 1U : 0U, this_script_check ? 1U : 0U})
                    .at(0));
        },
        py::arg("ped_type"), py::arg("model_hash"), py::arg("coordinates"), py::arg("heading") = 0.0F,
        py::arg("is_network") = true, py::arg("this_script_check") = true);
    auto vehicle = module.def_submodule("vehicle", "VEHICLE natives");
    vehicle.def(
        "create",
        [](const std::uint32_t model_hash, const Vec3 coordinates, const float heading, const bool is_network,
           const bool this_script_check) {
            validate_model_hash(model_hash);
            validate_coordinate(coordinates.x, "x");
            validate_coordinate(coordinates.y, "y");
            validate_coordinate(coordinates.z, "z");
            validate_coordinate(heading, "heading");
            return static_cast<int>(
                call_game("VEHICLE_CREATE",
                          {model_hash, float_bits(coordinates.x), float_bits(coordinates.y), float_bits(coordinates.z),
                           float_bits(heading), is_network ? 1U : 0U, this_script_check ? 1U : 0U})
                    .at(0));
        },
        py::arg("model_hash"), py::arg("coordinates"), py::arg("heading") = 0.0F, py::arg("is_network") = true,
        py::arg("this_script_check") = true);
}

void execute_script(const std::filesystem::path script) {
    launcher::diagnostics::log(L"INFO", L"Python", L"Starting script: " + script.wstring());
    try {
        launcher::diagnostics::log(L"INFO", L"Python", L"Waiting for the Python GIL.");
        py::gil_scoped_acquire gil;
        launcher::diagnostics::log(L"INFO", L"Python", L"Python GIL acquired.");
        py::dict globals;
        globals["__name__"] = "__main__";
        globals["__file__"] = script.string();
        launcher::diagnostics::log(L"INFO", L"Python", L"Importing Python sys module.");
        auto sys = py::module_::import("sys");
        auto make_stream = [](const char* channel) {
            py::object stream = py::module_::import("types").attr("SimpleNamespace")();
            stream.attr("write") = py::cpp_function([channel](const std::string& text) {
                if (!text.empty() && text != "\n") {
                    append_console(std::string("[") + channel + "] " + text);
                }
                return text.size();
            });
            stream.attr("flush") = py::cpp_function([] {});
            return stream;
        };
        sys.attr("stdout") = make_stream("stdout");
        sys.attr("stderr") = make_stream("stderr");
        launcher::diagnostics::log(L"INFO", L"Python", L"Evaluating script file.");
        py::eval_file(script.string(), globals);
        append_console("[info] Script completed: " + script.filename().string());
    } catch (const py::error_already_set& error) {
        const std::string message = "[python] " + std::string(error.what());
        append_console(message);
        launcher::diagnostics::log(L"ERROR", L"Python", wide_from_utf8(message));
    } catch (const std::exception& error) {
        const std::string message = "[runtime] " + std::string(error.what());
        append_console(message);
        launcher::diagnostics::log(L"ERROR", L"Python", wide_from_utf8(message));
    }
    runtime_running = false;
    launcher::diagnostics::log(L"INFO", L"Python", L"Script worker stopped: " + script.wstring());
}

} // namespace

void initialize() {
    std::call_once(python_once, [] {
        wchar_t module_path[MAX_PATH]{};
        HMODULE client_module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&initialize), &client_module);
        const DWORD length = GetModuleFileNameW(client_module, module_path, MAX_PATH);
        const auto runtime_directory =
            length == 0 ? std::filesystem::current_path() : std::filesystem::path(module_path).parent_path();
        const auto settings = launcher::config::load(runtime_directory);
        scripts_directory = settings.scripts_directory;
        std::error_code error;
        std::filesystem::create_directories(scripts_directory, error);
        if (error) {
            launcher::diagnostics::log(L"ERROR", L"Python", L"Cannot create scripts directory.");
        }
        py::initialize_interpreter();
        const auto venv_site_packages = settings.site_packages_directory;
        if (std::filesystem::is_directory(venv_site_packages)) {
            py::module_::import("sys").attr("path").attr("insert")(0, venv_site_packages.string());
            append_console("[info] Added configured Python site-packages to sys.path.");
        } else {
            append_console("[warning] Configured Python site-packages directory is missing.");
        }
        try {
            py::module_::import("encodings.idna");
            append_console("[info] Python IDNA codec initialized.");
        } catch (const py::error_already_set& error) {
            const std::string message = "[python] Could not initialize IDNA codec: " + std::string(error.what());
            append_console(message);
            launcher::diagnostics::log(L"ERROR", L"Python", wide_from_utf8(message));
        }
        append_console("[info] Python runtime initialized.");

        // Keep the interpreter available to script worker threads after this
        // initialization thread exits. A scope guard would reacquire the GIL
        // at the end of this callback and block every later script worker.
        PyEval_SaveThread();
        launcher::diagnostics::log(L"INFO", L"Python", L"Python GIL released for script workers.");
    });
}

void shutdown() {
    stop_requested = true;
    {
        std::lock_guard lock(request_mutex);
        while (!requests.empty()) {
            requests.front()->completion.set_exception(
                std::make_exception_ptr(std::runtime_error("Python runtime is shutting down")));
            requests.pop();
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
    runtime_running = false;
    if (Py_IsInitialized()) {
        py::finalize_interpreter();
    }
}

void pump_game_thread() {
    std::unique_ptr<NativeRequest> request;
    {
        std::lock_guard lock(request_mutex);
        if (requests.empty()) {
            return;
        }
        request = std::move(requests.front());
        requests.pop();
    }
    try {
        std::uint64_t hash = 0;
        std::size_t result_count = 0;
        if (request->operation == "PLAYER_GET_PED") {
            hash = 0x43A66C31C68491C0ULL;
            result_count = 1;
        } else if (request->operation == "ENTITY_EXISTS") {
            hash = 0x7239B21A38F536BAULL;
            result_count = 1;
        } else if (request->operation == "ENTITY_HEALTH") {
            hash = 0xEEF059FAD016D209ULL;
            result_count = 1;
        } else if (request->operation == "ENTITY_COORDS") {
            hash = 0x3FEF770D40960D5AULL;
            result_count = 3;
        } else if (request->operation == "ENTITY_SET_COORDS") {
            hash = 0x06843DA7060A026BULL;
        } else if (request->operation == "PED_CREATE") {
            hash = 0xD49F9B0955C367DEULL;
            result_count = 1;
        } else if (request->operation == "VEHICLE_CREATE") {
            hash = 0xAF35D0D2583051B0ULL;
            result_count = 1;
        } else {
            throw std::invalid_argument("unknown native operation: " + request->operation);
        }
        request->completion.set_value(game::invoke_native(hash, request->arguments, result_count));
    } catch (...) {
        request->completion.set_exception(std::current_exception());
    }
}

std::vector<std::filesystem::path> scripts() {
    // The overlay can render before the client initialization worker finishes.
    // Initialize lazily so the first UI frame still sees the configured folder.
    initialize();
    std::vector<std::filesystem::path> result;
    std::error_code error;
    if (!std::filesystem::exists(scripts_directory, error)) {
        launcher::diagnostics::log(L"WARNING", L"Python",
                                   L"Scripts directory does not exist: " + scripts_directory.wstring());
        return result;
    }
    for (const auto& entry : std::filesystem::directory_iterator(scripts_directory, error)) {
        if (entry.is_regular_file() && entry.path().extension() == ".py") {
            result.push_back(entry.path());
        }
    }
    // launcher::diagnostics::log(L"INFO", L"Python",
    //                            L"Discovered Python scripts: " + std::to_wstring(result.size()));
    std::sort(result.begin(), result.end());
    return result;
}

bool run(const std::filesystem::path& script) {
    if (runtime_running) {
        append_console("[warning] A Python script is already running.");
        launcher::diagnostics::log(L"WARNING", L"Python", L"Run request rejected because another script is active.");
        return false;
    }
    std::error_code error;
    const auto normalized_script = std::filesystem::weakly_canonical(script, error);
    const auto normalized_directory = std::filesystem::weakly_canonical(scripts_directory, error);
    if (error || normalized_script.extension() != ".py" || normalized_script.parent_path() != normalized_directory) {
        append_console("[error] The selected script is outside the configured scripts directory.");
        launcher::diagnostics::log(L"ERROR", L"Python",
                                   L"Run request rejected for invalid script path: " + script.wstring());
        return false;
    }
    if (!std::filesystem::is_regular_file(normalized_script, error) || error) {
        append_console("[error] The selected Python script does not exist or is not a regular file.");
        launcher::diagnostics::log(L"ERROR", L"Python", L"Script file is unavailable: " + normalized_script.wstring());
        return false;
    }
    if (worker.joinable()) {
        worker.join();
    }
    stop_requested = false;
    current_script_name = normalized_script.filename().string();
    runtime_running = true;
    worker = std::thread(execute_script, normalized_script);
    append_console("[info] Running: " + current_script_name);
    return true;
}

void stop() {
    stop_requested = true;
    append_console("[info] Stop requested. Python code must return from the current call.");
}

bool running() {
    return runtime_running.load();
}
std::string active_script() {
    return current_script_name;
}
std::vector<std::string> console_lines() {
    std::lock_guard lock(state_mutex);
    return output;
}
void clear_console() {
    std::lock_guard lock(state_mutex);
    output.clear();
}

} // namespace client::python
