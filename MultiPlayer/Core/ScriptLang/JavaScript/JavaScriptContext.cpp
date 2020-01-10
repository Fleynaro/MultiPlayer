#include "JavaScriptContext.h"



JavaScriptModule::JavaScriptModule(
	JavaScriptContext* context,
	FS::File file,
	std::string entryName,
	v8::Local<v8::Value> extra
)
	: m_scriptFile(file), m_context(context)
{
	v8::HandleScope handle_scope(getIsolate());

	v8::Local<v8::ObjectTemplate> global =
		v8::Local<v8::ObjectTemplate>::New(getIsolate(), getGlobal(getIsolate()));

	v8::Local<v8::Context> js_context = v8::Context::New(getIsolate(), NULL, global);
	m_js_context.Reset(getIsolate(), js_context);

	v8::Context::Scope context_scope(js_context);
	setGlobalObjects(js_context, extra);
	getContext()->setCurrentModule(this);

	auto scriptCode = FS::ScriptFileDesc(file).getData();
	JavaScript::executeScript(
		v8::String::NewFromUtf8(getIsolate(), scriptCode.c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
		getIsolate()
	);

	executeEntryFunction(entryName);

	m_js_export.Reset(
		getIsolate(),
		getExportObjectFromContext(js_context)
	);
}

inline JavaScriptModule::~JavaScriptModule() {
	for (auto it : m_listeners) {
		delete it;
	}
}

v8::Local<v8::Value> JavaScriptModule::getExportObjectFromContext(v8::Local<v8::Context>& context)
{
	v8::Local<v8::Value> result;
	if (context->Global()->Get(context,
		v8::String::NewFromUtf8(getIsolate(), "exports", v8::NewStringType::kNormal).ToLocalChecked()
	).ToLocal(&result) && result->IsObject()) {
		return result;
	}

	auto module = getModuleObject(context);
	if (module->IsObject())
	{
		if (module->ToObject(getIsolate())->Get(context,
			v8::String::NewFromUtf8(getIsolate(), "exports", v8::NewStringType::kNormal).ToLocalChecked()
		).ToLocal(&result) && !result->IsUndefined()) {
			return result;
		}
	}

	return v8::Undefined(getIsolate());
}

v8::Local<v8::Value> JavaScriptModule::getExportObject() {
	return v8::Local<v8::Value>::New(getIsolate(), m_js_export);
}

void JavaScriptModule::executeEntryFunction(std::string entryName) {
	auto result = JavaScript::callFunction(
		getEntryFunction(entryName)
	);

	if (result->IsInt32()) {
		auto iResult = v8::Local<v8::Integer>::Cast(result)->ToInt32(getIsolate())->Value();
		if (iResult == 0) {
			//success
		}
	}
}

v8::Local<v8::Function> JavaScriptModule::getEntryFunction(std::string entryName) {
	v8::Local<v8::String> entry_name =
		v8::String::NewFromUtf8(
			getIsolate(),
			entryName.c_str(),
			v8::NewStringType::kNormal
		).ToLocalChecked();

	v8::Local<v8::Value> entry_val;
	auto context = getIsolate()->GetCurrentContext();
	if (!context->Global()->Get(context, entry_name).ToLocal(&entry_val) ||
		!entry_val->IsFunction()) {
		//throw ex
	}

	return v8::Local<v8::Function>::Cast(entry_val);
}

void JavaScriptModule::addEventListener(std::string name, v8::Local<v8::Value> fn)
{
	auto module_listener = new JavaScriptModuleListener(this, fn);
	m_listeners.push_back(module_listener);

	auto listener = ScriptContextCallback::createEventListenerByName(getContext(), module_listener, name);
	if (listener == nullptr) {
		//throw ex
		return;
	}
	module_listener->setListener(listener);
	listener->setPriority(JavaScriptContext::Priority::LOW);
}

void JavaScriptModule::addEventListener_V8(const v8::FunctionCallbackInfo<v8::Value>& args)
{
	if (!args[0]->IsString() ||
		!(args[1]->IsFunction() || args[1]->IsObject())) {
		//throw ex
		return;
	}

	v8::String::Utf8Value name(args.GetIsolate(), args[0]);

	auto module = JavaScriptContext::getCurrentJavaScriptContext()->getCurrentModule();
	module->addEventListener(
		*name,
		args[1]
	);
}

JavaScriptModule* JavaScriptModule::require(
	FS::File file,
	std::string entryName = "",
	v8::Local<v8::Value> extra = v8::Undefined(v8::Isolate::GetCurrent())
)
{
	if (entryName.length() == 0) {
		entryName = getContext()->getScriptMod()->getEntryFunction();
	}

	auto module = new JavaScriptModule(getContext(), file, entryName, extra);
	getContext()->addModule(module);
	return module;
}

void JavaScriptModule::require_V8(const v8::FunctionCallbackInfo<v8::Value>& args)
{
	if (!args[0]->IsString()) {
		//throw ex
		return;
	}
	std::string addonName = *v8::String::Utf8Value(args.GetIsolate(), args[0]);
	Generic::String::Replace(addonName, "/", "\\");

	auto module = JavaScriptContext::getCurrentJavaScriptContext()->getCurrentModule();
	auto calledModuleFile = FS::File(
		module->getScriptFile().getDirectory().getPath() + "\\" + addonName
	);
	if (!calledModuleFile.exists()) {
		//throw ex
	}

	v8::Local<v8::Value> extra;
	if (args.Length() > 1) {
		extra = args[1];
	}
	else {
		extra = v8::Undefined(v8::Isolate::GetCurrent());
	}

	std::string entryName = "";
	if (args[2]->IsString()) {
		entryName = *v8::String::Utf8Value(args.GetIsolate(), args[2]);
	}
	auto calledModule = module->require(calledModuleFile, entryName, extra);
	
	args.GetReturnValue().Set(
		calledModule->getExportObject()
	);
}

v8::Isolate* JavaScriptModule::getIsolate() {
	return getContext()->getIsolate();
}

v8::Global<v8::Context>& JavaScriptModule::getJsContext() {
	return m_js_context;
}

JavaScriptContext* JavaScriptModule::getContext() {
	return m_context;
}

v8::Local<v8::Value> JavaScriptModule::getModuleObject(v8::Local<v8::Context>& context) {
	v8::Local<v8::Value> module;
	if (!context->Global()->Get(context, v8::String::NewFromUtf8(getIsolate(), "module", v8::NewStringType::kNormal).ToLocalChecked()).ToLocal(&module) ||
		!module->IsObject()) {
		return v8::Undefined(getIsolate());
	}
	return module;
}

void JavaScriptModule::setGlobalObjects(v8::Local<v8::Context>& context, v8::Local<v8::Value> &extra)
{
	v8::Local<v8::Value> module = getModuleObject(context);

	module->ToObject(getIsolate())->Set(
		v8::String::NewFromUtf8(getIsolate(), "directory", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::String::NewFromUtf8(
			getIsolate(),
			getScriptFile().getDirectory().getPath().c_str(),
			v8::NewStringType::kNormal
		).ToLocalChecked()
	);
	module->ToObject(getIsolate())->Set(
		v8::String::NewFromUtf8(getIsolate(), "filename", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::String::NewFromUtf8(
			getIsolate(),
			getScriptFile().getFullname().c_str(),
			v8::NewStringType::kNormal
		).ToLocalChecked()
	);

	//extra
	module->ToObject(getIsolate())->Set(
		v8::String::NewFromUtf8(getIsolate(), "extra", v8::NewStringType::kNormal).ToLocalChecked(),
		extra
	);
}

FS::File& JavaScriptModule::getScriptFile() {
	return m_scriptFile;
}

//set global template objects and functions

void JavaScriptModule::setGlobalTemplateObjects(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate>& global)
{
	//Module
	v8::Local<v8::ObjectTemplate> Module
		= v8::ObjectTemplate::New(v8::Isolate::GetCurrent());
	global->Set(
		v8::String::NewFromUtf8(isolate, "module", v8::NewStringType::kNormal).ToLocalChecked(),
		Module
	);

	//SDK
	v8::Local<v8::ObjectTemplate> SDK
		= v8::ObjectTemplate::New(v8::Isolate::GetCurrent());
	for (auto it : Class::Environment::getClasses()) {
		SDK->Set(
			v8::String::NewFromUtf8(isolate, it->getName().c_str(), v8::NewStringType::kNormal).ToLocalChecked(),
			it->V8_MakeTemplate()
		);
	}

	global->Set(
		v8::String::NewFromUtf8(isolate, "SDK", v8::NewStringType::kNormal).ToLocalChecked(),
		SDK
	);


	//Require
	global->Set(
		v8::String::NewFromUtf8(isolate, "require", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::FunctionTemplate::New(isolate, require_V8)
	);


	//Event
	v8::Local<v8::ObjectTemplate> Event
		= v8::ObjectTemplate::New(v8::Isolate::GetCurrent());
	Event->Set(
		v8::String::NewFromUtf8(isolate, "addListener", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::FunctionTemplate::New(isolate, addEventListener_V8)
	);

	global->Set(
		v8::String::NewFromUtf8(isolate, "Event", v8::NewStringType::kNormal).ToLocalChecked(),
		Event
	);

	//for debug - print (TODO: wrapper for message windows)
	global->Set(
		v8::String::NewFromUtf8(isolate, "printw", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::FunctionTemplate::New(isolate, JavaScript::V8_showWinMessage)
	);
	
	global->Set(
		v8::String::NewFromUtf8(isolate, "print", v8::NewStringType::kNormal).ToLocalChecked(),
		v8::FunctionTemplate::New(isolate, JavaScriptContext::V8_addLogMessage)
	);
}

JavaScriptContext::~JavaScriptContext() {
	for (auto it : m_modules) {
		delete it;
	}
}
