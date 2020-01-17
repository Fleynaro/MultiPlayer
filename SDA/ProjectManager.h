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
			getProgramExe()->initGhidraClient();
			getProgramExe()->initManagers();
			getProgramExe()->load();

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

#include <Utility/FileWrapper.h>
class ProjectManager
{
public:
	ProjectManager(const FS::File& file)
		: m_projectsFile(file)
	{}

	void loadProjects() {
		if (!getProjectsFile().exists()) {
			createProjectsFile();
			return;
		}

		FS::JsonFileDesc projectsFile(getProjectsFile());
		if (projectsFile.isOpen()) {
			json data = projectsFile.getData();
			if (!data["projects"].is_array()) {
				return;
			}

			for (auto projectInfo : data["projects"]) {
				if (!projectInfo.is_object() || !projectInfo["name"].is_string() || !projectInfo["dir"].is_string())
					continue;
				auto projectDir = FS::Directory(projectInfo["dir"]);
				if (doesProjectExists(projectDir)) {
					createProject(projectInfo["name"], projectDir);
				}
			}
		}
	}

	void saveProjects() {
		FS::JsonFileDesc projectsFile(getProjectsFile(), std::ios::out);
		if (projectsFile.isOpen()) {
			json data;
			data["projects"] = std::list<json>();
			int idx = 0;
			for (auto project : m_projects) {
				data["projects"][idx]["name"] = project->getName();
				data["projects"][idx]["dir"] = project->getDirectory().getPath();
				idx++;
			}
			projectsFile.setData(data);
		}
	}

	void createProjectsFile() {
		saveProjects();
	}

	auto& getProjects() {
		return m_projects;
	}

	Project* createProject(const std::string& name, const FS::Directory& projectDir) {
		Project* project = new Project(name, projectDir);
		m_projects.push_back(project);
		return project;
	}

	void setCurrentProject(Project* project) {
		m_currentProject = project;
	}

	Project* getCurrentProject() {
		return m_currentProject;
	}

	bool isAnyProjectActive() {
		return getCurrentProject() != nullptr;
	}

	FS::File& getProjectsFile() {
		return m_projectsFile;
	}

	FS::Directory& getDefaultDirectory() {
		return getProjectsFile().getDirectory();
	}

	static bool doesProjectExists(const FS::Directory& dir) {
		return FS::File(dir, Project::m_projectFileName).exists();
	}
private:
	FS::File m_projectsFile;
	Project* m_currentProject = nullptr;
	std::list<Project*> m_projects;
};