#pragma once

#include "V8_include.h"
#include "../IScriptLangContext.h"


class JavaScript
{
public:
	static void init()
	{
		using namespace v8;
		auto platform = platform::NewDefaultPlatform();
		V8::InitializePlatform(platform.get());
		V8::Initialize();

		Isolate::CreateParams create_params;
		create_params.array_buffer_allocator =
			ArrayBuffer::Allocator::NewDefaultAllocator();
		
		m_isolate = Isolate::New(create_params);
		m_platform = std::move(platform);
	}

	static v8::Isolate* getIsolate() {
		return m_isolate;
	}

	static v8::Local<v8::Value> executeScript(
		v8::Local<v8::String> script,
		v8::Isolate* isolate = v8::Isolate::GetCurrent()
	)
	{
		v8::TryCatch try_catch(isolate);

		v8::Local<v8::Context> context(isolate->GetCurrentContext());
		
		v8::Local<v8::Script> compiled_script;
		if (!v8::Script::Compile(context, script).ToLocal(&compiled_script)) {
			v8::String::Utf8Value error(isolate, try_catch.Exception());
			//throw ex
			MessageBox(NULL, *error, NULL, MB_ICONEXCLAMATION | MB_OK);
		}
		
		v8::Local<v8::Value> result;
		if (!compiled_script->Run(context).ToLocal(&result)) {
			v8::String::Utf8Value error(isolate, try_catch.Exception());
			//throw ex
			MessageBox(NULL, *error, NULL, MB_ICONEXCLAMATION | MB_OK);
		}
		return result;
	}

	static v8::Local<v8::Value> callFunction(
		v8::Local<v8::Function> func,
		std::vector<v8::Local<v8::Value>> args = {},
		v8::Local<v8::Object> parent = v8::Isolate::GetCurrent()->GetCurrentContext()->Global(),
		v8::Isolate* isolate = v8::Isolate::GetCurrent()
	)
	{
		v8::TryCatch try_catch(isolate);
		
		v8::Local<v8::Value> result;
		if (!func->Call(isolate->GetCurrentContext(), parent, (int)args.size(), &args[0]).ToLocal(&result)) {
			v8::String::Utf8Value error(isolate, try_catch.Exception());
			//throw ex
			MessageBox(NULL, *error, NULL, MB_ICONEXCLAMATION | MB_OK);
		}
		return result;
	}

	static void V8_showWinMessage(const v8::FunctionCallbackInfo<v8::Value>& args)
	{
		if (!args[0]->IsString()) {
			//throw ex
			return;
		}

		v8::String::Utf8Value message(args.GetIsolate(), args[0]);
		MessageBox(NULL, *message, NULL, MB_ICONEXCLAMATION | MB_OK);
	}

	static inline v8::Isolate* m_isolate = nullptr;
	static inline std::unique_ptr<v8::Platform> m_platform;
};



class JavaScriptContext;
class JavaScriptModuleListener;
class JavaScriptModule
{
public:
	JavaScriptModule(JavaScriptContext* context, FS::File file, std::string entryName, v8::Local<v8::Value> extra);
	
	~JavaScriptModule();

	v8::Local<v8::Value> getExportObjectFromContext(v8::Local<v8::Context>& context);

	v8::Local<v8::Value> getExportObject();

	void executeEntryFunction(std::string entryName);

	v8::Local<v8::Function> getEntryFunction(std::string entryName);

	void addEventListener(std::string name, v8::Local<v8::Value> fn);

	static void addEventListener_V8(const v8::FunctionCallbackInfo<v8::Value>& args);

	JavaScriptModule* require(FS::File file, std::string entryName, v8::Local<v8::Value> extra);

	static void require_V8(const v8::FunctionCallbackInfo<v8::Value>& args);

	v8::Isolate* getIsolate();

	v8::Global<v8::Context>& getJsContext();

	JavaScriptContext* getContext();

	v8::Local<v8::Value> getModuleObject(v8::Local<v8::Context>& context);

	void setGlobalObjects(v8::Local<v8::Context>& context, v8::Local<v8::Value>& extra);

	FS::File& getScriptFile();
private:
	FS::File m_scriptFile;
	std::list<JavaScriptModuleListener*> m_listeners;
	v8::Global<v8::Context> m_js_context;
	v8::Global<v8::Value> m_js_export;
	JavaScriptContext* m_context = nullptr;


	static v8::Global<v8::ObjectTemplate>& getGlobal(v8::Isolate* isolate) {
		static v8::Global<v8::ObjectTemplate> js_global;
		if (!js_global.IsEmpty()) {
			return js_global;
		}

		v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
		setGlobalTemplateObjects(isolate, global);

		js_global.Reset(isolate, global);
		return js_global;
	}

	//set global template objects and functions
	static void setGlobalTemplateObjects(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate>& global);
};

//for events to listen them
class JavaScriptModuleListener
{
public:
	JavaScriptModuleListener(JavaScriptModule* module, v8::Local<v8::Value> value)
		: m_module(module)
	{
		m_global.Reset(v8::Isolate::GetCurrent(), value);
	}
	~JavaScriptModuleListener() {
		IGameEventGenPublisher::removeEventHandler(m_listener);
	}

	void setListener(IGameEventHandler* listener) {
		m_listener = listener;
		IGameEventGenPublisher::addEventHandler(m_listener);
	}

	JavaScriptModule* getModule() {
		return m_module;
	}

	v8::Local<v8::Value> getValue() {
		return v8::Local<v8::Value>::New(
			v8::Isolate::GetCurrent(),
			m_global
		);
	}
private:
	JavaScriptModule* m_module;
	v8::Global<v8::Value> m_global;
	IGameEventHandler* m_listener = nullptr;
};


//separated fiber for executing javascript code
class JavaScriptContext : public IScriptLangContext
{
public:
	JavaScriptContext(v8::Isolate* isolate, std::shared_ptr<Script::Mod> mod)
		: m_js_isolate(isolate), IScriptLangContext(mod) {}
	~JavaScriptContext();

	Type getType() override {
		return Type::JavaScript;
	}

	IGameScriptContext* getCopyInstance() override {
		return new JavaScriptContext(m_js_isolate, m_mod);
	}

	void addModule(JavaScriptModule* module) {
		m_modules.push_back(module);
	}

	JavaScriptModule* getCurrentModule() {
		return m_curModule;
	}

	void setCurrentModule(JavaScriptModule* module) {
		m_curModule = module;
	}

	void OnExecuteFiber() override
	{
		v8::Isolate::Scope isolate_scope(getIsolate());
		v8::HandleScope handle_scope(getIsolate());
		ExecuteFiber();
	}

	void OnInit() override
	{
		IScriptLangContext::OnInit();
		
		m_mainModule = new JavaScriptModule(
			this,
			getScriptMod()->getMainExecutionFile(),
			getScriptMod()->getEntryFunction(),
			v8::Undefined(getIsolate())
		);
		addModule(m_mainModule);
	}

	void OnAnyCallback(void* ptr, std::string name, Class::Adapter::ICallback* callback) override
	{
		std::vector<v8::Local<v8::Value>> params;
		callback->V8_getParams(params, getIsolate());

		v8::HandleScope handle_scope(getIsolate());

		//get the module listener
		auto module_listener = (JavaScriptModuleListener*)ptr;

		//enter the module context
		v8::Context::Scope context_scope(
			v8::Local<v8::Context>::New(
				getIsolate(),
				module_listener->getModule()->getJsContext()
			)
		);
		setCurrentModule(module_listener->getModule());

		//get the module listener value
		auto listener_val = module_listener->getValue();

		//transform to js object
		v8::Local<v8::String> fn_name =
			v8::String::NewFromUtf8(
				getIsolate(),
				name.c_str(),
				v8::NewStringType::kNormal
			).ToLocalChecked();

		//check what it is object that store function or directly function
		v8::Local<v8::Value> result;
		if (listener_val->IsFunction())
		{
			auto listener_fun = v8::Local<v8::Function>::Cast(listener_val);
			//pass fn_name as the last param
			params.push_back(fn_name);
			//call function callback in global space
			result = JavaScript::callFunction(
				listener_fun,
				params
			);
		}
		else if (listener_val->IsObject())
		{
			auto listener_obj = listener_val->ToObject(getIsolate());

			//find declared function callback
			v8::Local<v8::Value> fn_val;
			if (!listener_obj->Get(getIsolate()->GetCurrentContext(), fn_name).ToLocal(&fn_val) || !fn_val->IsFunction())	{
				//throw ex
				return;
			}

			//call function callback in object handler space
			result = JavaScript::callFunction(
				v8::Local<v8::Function>::Cast(fn_val),
				params,
				listener_obj
			);
		}

		//get the result of callback exucution complete
		if (result->IsInt32()) {
			auto iResult = v8::Local<v8::Integer>::Cast(result)->ToInt32(getIsolate())->Value();
			if (iResult == 0) {
				//success
			}
		}
	}

	void OnTick() override
	{
		
	}

	static void V8_addLogMessage(const v8::FunctionCallbackInfo<v8::Value>& args)
	{
		if (!args[0]->IsString()) {
			//throw ex
			return;
		}

		v8::String::Utf8Value message(args.GetIsolate(), args[0]);
		getCurrentJavaScriptContext()->addConsoleMessage(*message);
	}

	//get the current context among js ones
	static JavaScriptContext* getCurrentJavaScriptContext() {
		return (JavaScriptContext*)GameScriptEngine::getCurrentScriptExeContext();
	}

	v8::Isolate* getIsolate() {
		return m_js_isolate;
	}
private:
	v8::Isolate* m_js_isolate;
	JavaScriptModule* m_mainModule = nullptr;
	JavaScriptModule* m_curModule = nullptr;
	std::list<JavaScriptModule*> m_modules;
};