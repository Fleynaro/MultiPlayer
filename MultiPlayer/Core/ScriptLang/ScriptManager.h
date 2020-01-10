#pragma once


#include "main.h"
#include "Utility/FileWrapper.h"
#include "Utility/Config.h"


namespace Cfg
{
	class ScriptMod : public Config, public IJsonInit
	{
	public:
		ScriptMod() {
			defaultInit();
		}

		void defaultInit() override {
			(*this)
				.setValue("version", new Value<std::string>("v1.0.0"))
				.beginConfig("entry")
					.setValue("file", new Value<std::string>("index.js"))
					.setValue("function", new Value<std::string>("Main"))
				.endConfig();
		}

		void initByJson(json& j) override {
			if (j["version"].is_string())
				*getValue<std::string>("version") = j["version"].get<std::string>();
			
			if (j["entry"].is_object())
			{
				if (j["entry"]["file"].is_string())
					*getConfig("entry").getValue<std::string>("file") = j["entry"]["file"].get<std::string>();
				if (j["entry"]["file"].is_string())
					*getConfig("entry").getValue<std::string>("function") = j["entry"]["function"].get<std::string>();
			}
		}
	};
};

namespace Script
{
	//script file
	class File
	{
	public:
		File(FS::File file) : m_file(file) {}

		FS::File getFile() {
			return m_file;
		}
	private:
		FS::File m_file;
	};

	//mod directory
	class Mod
	{
	public:
		Mod(FS::Directory dir) : m_dir(dir) {
			auto jsonDesc = FS::JsonFileDesc(
				getConfigFile()
			);
			if (!jsonDesc.isOpen()) {
				//throw ex
			}
			auto data = jsonDesc.getData();
			m_cfg.initByJson(data);
		}

		FS::File getMainExecutionFile() {
			return FS::File(
				getDirectory(),
				*m_cfg.getConfig("entry").getValue<std::string>("file")
			);
		}

		std::string getEntryFunction() {
			return *m_cfg.getConfig("entry").getValue<std::string>("function");
		}

		FS::File getConfigFile() {
			return FS::File(m_dir, "config.json");
		}

		FS::Directory getDirectory() {
			return m_dir;
		}
	private:
		FS::Directory m_dir;
		Cfg::ScriptMod m_cfg;
	};
};