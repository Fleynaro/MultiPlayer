#pragma once
#include <Manager/Managers.h>
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
		m_program = new CE::ProgramModule(moduleDir);
		load();
	}

	void load() {
		if (!isValid()) {
			return;
		}

		try {
			/*getProgramModule()->initDataBase("general.db");
			getProgramModule()->initManagers();
			getProgramModule()->initGhidraClient();
			getProgramModule()->load();

			auto dataTypeGhidraManager = getProgramModule()->getTypeManager()->getGhidraManager();
			dataTypeGhidraManager->updateAll();
			auto hashMap = dataTypeGhidraManager->generateHashMap();
			dataTypeGhidraManager->updateTypedefs(hashMap);
			dataTypeGhidraManager->updateEnums(hashMap);
			dataTypeGhidraManager->updateStructures(hashMap);

			auto functionGhidraManager = getProgramModule()->getFunctionManager()->getGhidraManager();
			functionGhidraManager->update(
				functionGhidraManager->generateHashMap()
			);
			getProgramModule()->getFunctionManager()->buildFunctionBodies();
			getProgramModule()->getFunctionManager()->buildFunctionBasicInfo();*/

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

	CE::ProgramModule* getProgramModule() {
		return m_program;
	}
private:
	std::string m_name;
	std::string m_desc;
	FS::Directory m_dir;

	CE::ProgramModule* m_program = nullptr;
};