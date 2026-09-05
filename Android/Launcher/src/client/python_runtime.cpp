#include "client/python_runtime.h"

#include "client/game_hooks.h"
#include "common/config.h"
#include "common/diagnostics.h"
#include "native_bindings.h"

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

std::uint64_t native_argument(const py::handle value, std::vector<std::string>& string_storage) {
    if (py::isinstance<py::bool_>(value)) {
        return py::cast<bool>(value) ? 1U : 0U;
    }
    if (py::isinstance<py::int_>(value)) {
        const auto integer = py::cast<std::int64_t>(value);
        if (integer < 0) {
            return static_cast<std::uint64_t>(integer);
        }
        return static_cast<std::uint64_t>(integer);
    }
    if (py::isinstance<py::float_>(value)) {
        const auto number = py::cast<float>(value);
        if (!std::isfinite(number)) {
            throw std::invalid_argument("native float arguments must be finite");
        }
        return float_bits(number);
    }
    if (py::isinstance<py::str>(value)) {
        string_storage.push_back(py::cast<std::string>(value));
        return reinterpret_cast<std::uint64_t>(string_storage.back().c_str());
    }
    if (py::isinstance<Vec3>(value)) {
        const auto vector = py::cast<Vec3>(value);
        validate_coordinate(vector.x, "x");
        validate_coordinate(vector.y, "y");
        validate_coordinate(vector.z, "z");
        throw std::invalid_argument("Vector3 arguments are not supported by this native signature");
    }
    throw py::type_error("native arguments must be bool, int, float, or str");
}

void validate_native_argument(const py::handle value, const std::string_view type) {
    const bool pointer = type.ends_with('*');
    const auto base_type = pointer ? type.substr(0, type.size() - 1) : type;
    if (base_type == "bool" && !py::isinstance<py::bool_>(value)) {
        throw py::type_error("native boolean arguments must be bool");
    }
    if ((base_type == "int" || base_type == "Hash" || base_type == "Entity" || base_type == "Ped" ||
         base_type == "Vehicle" || base_type == "Object" || base_type == "Pickup" || base_type == "Blip") &&
        !py::isinstance<py::int_>(value)) {
        throw py::type_error("native handle and integer arguments must be int");
    }
    if ((base_type == "Entity" || base_type == "Ped" || base_type == "Vehicle" || base_type == "Object" ||
         base_type == "Pickup" || base_type == "Blip") &&
        py::cast<std::int64_t>(value) <= 0) {
        throw std::invalid_argument("native handles must be positive");
    }
    if (base_type == "str" && !py::isinstance<py::str>(value)) {
        throw py::type_error("native text arguments must be str");
    }
    if (base_type == "Vector3" && !py::isinstance<Vec3>(value)) {
        throw py::type_error("native vector arguments must be gta.Vector3");
    }
    if (base_type == "float" && !py::isinstance<py::float_>(value) && !py::isinstance<py::int_>(value)) {
        throw py::type_error("native floating-point arguments must be float or int");
    }
}

void bind_generated_natives(py::module_& module) {
    for (const auto& spec : generated_natives) {
        auto group = module.attr(spec.group.data());
        group.attr(spec.python_name.data()) = py::cpp_function([spec](const py::args& arguments) -> py::object {
            if (arguments.size() != spec.argc) {
                throw py::type_error(std::string(spec.original) + " expects " + std::to_string(spec.argc) +
                                     " positional arguments, got " + std::to_string(arguments.size()));
            }
            std::vector<std::string> string_storage;
            string_storage.reserve(arguments.size());
            std::vector<std::uint64_t> native_arguments;
            native_arguments.reserve(arguments.size());
            std::vector<std::uint64_t> pointer_storage;
            pointer_storage.resize(arguments.size());
            std::vector<Vec3> vector_pointer_storage(arguments.size());
            std::vector<std::string_view> parameter_types;
            for (std::size_t begin = 0, end = 0; begin < spec.parameter_types.size(); begin = end + 1) {
                end = spec.parameter_types.find(',', begin);
                parameter_types.push_back(spec.parameter_types.substr(
                    begin, end == std::string_view::npos ? std::string_view::npos : end - begin));
                if (end == std::string_view::npos)
                    break;
            }
            std::size_t type_offset = 0;
            for (std::size_t index = 0; index < arguments.size(); ++index) {
                const auto argument = arguments[index];
                const auto separator = spec.parameter_types.find(',', type_offset);
                const auto type = spec.parameter_types.substr(type_offset, separator == std::string_view::npos
                                                                               ? std::string_view::npos
                                                                               : separator - type_offset);
                validate_native_argument(argument, type);
                if (type.ends_with('*')) {
                    const auto base_type = type.substr(0, type.size() - 1);
                    if (base_type == "Vector3") {
                        vector_pointer_storage[index] = py::cast<Vec3>(argument);
                        native_arguments.push_back(reinterpret_cast<std::uint64_t>(&vector_pointer_storage[index]));
                    } else {
                        pointer_storage[index] = native_argument(argument, string_storage);
                        native_arguments.push_back(reinterpret_cast<std::uint64_t>(&pointer_storage[index]));
                    }
                } else {
                    native_arguments.push_back(native_argument(argument, string_storage));
                }
                type_offset = separator == std::string_view::npos ? spec.parameter_types.size() : separator + 1;
            }
            const auto result_count = spec.result == "void" ? 0U : spec.result == "vector" ? 3U : 1U;
            const auto result = call_game("NATIVE_" + std::string(spec.original), std::move(native_arguments));
            if (result.size() != result_count) {
                throw std::runtime_error("native returned an invalid result count");
            }
            std::vector<py::object> values;
            if (spec.result == "void")
                values.push_back(py::none());
            else if (spec.result == "bool")
                values.push_back(py::bool_(result[0] != 0));
            else if (spec.result == "float")
                values.push_back(py::float_(bits_float(result[0])));
            else if (spec.result == "vector")
                values.push_back(py::cast(Vec3{bits_float(result[0]), bits_float(result[1]), bits_float(result[2])}));
            else if (spec.result == "string")
                values.push_back(py::str(reinterpret_cast<const char*>(result[0])));
            else
                values.push_back(py::int_(result[0]));
            for (std::size_t index = 0; index < parameter_types.size(); ++index) {
                const auto type = parameter_types[index];
                if (!type.ends_with('*'))
                    continue;
                const auto base_type = type.substr(0, type.size() - 1);
                if (base_type == "Vector3")
                    values.push_back(py::cast(vector_pointer_storage[index]));
                else if (base_type == "float")
                    values.push_back(py::float_(bits_float(pointer_storage[index])));
                else
                    values.push_back(py::int_(pointer_storage[index]));
            }
            if (values.size() == 1)
                return values.front();
            py::tuple tuple(values.size());
            for (std::size_t index = 0; index < values.size(); ++index)
                tuple[index] = values[index];
            return tuple;
        });
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
    module.def_submodule("player", "PLAYER natives");
    module.def_submodule("entity", "ENTITY natives");
    module.def_submodule("ped", "PED natives");
    module.def_submodule("vehicle", "VEHICLE natives");
    module.def_submodule("object", "OBJECT natives");
    module.def_submodule("task", "TASK natives");
    module.def_submodule("weapon", "WEAPON natives");
    module.def_submodule("world", "STREAMING, INTERIOR, FIRE, WATER, and ZONE natives");
    module.def_submodule("hud", "HUD natives");
    bind_generated_natives(module);
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
        if (request->operation.rfind("NATIVE_", 0) == 0) {
            const auto name = request->operation.substr(7);
            const auto native = std::find_if(generated_natives.begin(), generated_natives.end(),
                                             [&name](const auto& item) { return item.original == name; });
            if (native == generated_natives.end()) {
                throw std::invalid_argument("unknown generated native: " + name);
            }
            hash = native->hash;
            result_count = native->result == "void" ? 0U : native->result == "vector" ? 3U : 1U;
        } else {
            launcher::diagnostics::log(L"ERROR", L"Python",
                                       L"Unknown native operation requested: " + wide_from_utf8(request->operation));
            throw std::invalid_argument("unknown native operation: " + request->operation);
        }
        launcher::diagnostics::log(L"INFO", L"Python",
                                   L"Dispatching native operation '" + wide_from_utf8(request->operation) +
                                       L"' to the GTA game thread.");
        request->completion.set_value(game::invoke_native(hash, request->arguments, result_count));
    } catch (...) {
        launcher::diagnostics::log(L"ERROR", L"Python",
                                   L"Native operation failed: " + wide_from_utf8(request->operation));
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
