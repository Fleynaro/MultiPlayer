#pragma once
#include <Manager/Manager.h>
#include <GhidraSync/GhidraSync.h>
#include <Utility/DebugView.h>


class Project
{
public:
	inline static std::string m_projectFileName = "project.json";

	Project(const std::string& name, const FS::Directory& projectDir)
		: m_name(name), m_dir(projectDir)
	{}

	void loadProjectFile() {
		FS::JsonFileDesc projectFile(getProjectFile(), std::ios::in);

		if (projectFile.isOpen()) {
			json data = projectFile.getData();
			m_desc = data["description"];

		}
	}

	void saveProjectFile() {
		FS::JsonFileDesc projectFile(getProjectFile(), std::ios::out);

		if (projectFile.isOpen()) {
			json data;
			data["description"] = m_desc;
			projectFile.setData(data);
		}
	}

	void createProjectFile() {
		saveProjectFile();
	}

	void create() {
		createProjectFile();
		open();
	}

	void open() {
		auto moduleDir = getDirectory().next("Exe");
		moduleDir.createIfNotExists();
		m_programExe = new CE::ProgramExe(GetModuleHandle(NULL), moduleDir);
		load();
	}

	void load() {
		if (!isValid()) {
			return;
		}

		try {
			getProgramExe()->initDataBase("general.db");
			getProgramExe()->initManagers();
			getProgramExe()->initGhidraClient();
			getProgramExe()->load();

			getProgramExe()->getTypeManager()->getGhidraManager()->updateAll();
			getProgramExe()->getFunctionManager()->getGhidraManager()->update(
				getProgramExe()->getFunctionManager()->getGhidraManager()->generateHashMap()
			);
			getProgramExe()->getFunctionManager()->buildFunctionBodies();
			getProgramExe()->getFunctionManager()->buildFunctionBasicInfo();

		}
		catch (std::exception & e) {
			DebugOutput("exception: " + std::string(e.what()));
		}
	}
	
	bool isValid() {
		return getProjectFile().exists();
	}

	FS::File getProjectFile() {
		return FS::File(getDirectory(), m_projectFileName);
	}

	FS::Directory& getDirectory() {
		return m_dir;
	}

	std::string& getName() {
		return m_name;
	}

	std::string& getDesc() {
		return m_name;
	}

	CE::ProgramExe* getProgramExe() {
		return m_programExe;
	}
private:
	std::string m_name;
	std::string m_desc;
	FS::Directory m_dir;

	CE::ProgramExe* m_programExe = nullptr;
};