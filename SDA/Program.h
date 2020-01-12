#pragma once
#include <Manager/Manager.h>
#include <GhidraSync/GhidraSync.h>
#include <Utility/DebugView.h>


class Project
{
public:
	Project(const std::string& name, const FS::Directory& projectDir)
		: m_name(name), m_dir(projectDir)
	{}

	void load() {
		if (getProjectFile().exists()) {
			loadProjectFile();
		}
		
	}

	FS::File getProjectFile() {
		return FS::File(getDirectory(), "project.json");
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
private:
	std::string m_name;
	std::string m_desc;
	FS::Directory m_dir;

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
};

#include <Utility/FileWrapper.h>
class ProjectManager
{
public:
	ProjectManager(const FS::File& file)
		: m_projectsFile(file)
	{}

	void loadProjects() {
		if(!m_projectsFile.exists()) {
			createProjectsFile();
			return;
		}

		FS::JsonFileDesc projectsFile(m_projectsFile);
		if (projectsFile.isOpen()) {
			json data = projectsFile.getData();
			if (!data["projects"].is_array()) {
				return;
			}

			for (auto projectInfo : data["projects"]) {
				if (!projectInfo.is_object() || !projectInfo["name"].is_string() || !projectInfo["dir"].is_string())
					continue;
				auto projectDir = FS::Directory(projectInfo["dir"]);
				if (projectDir.exists()) {
					createProject(projectInfo["name"], projectDir);
				}
			}
		}
	}

	void saveProjects() {
		if (!m_projectsFile.exists()) {
			return;
		}

		FS::JsonFileDesc projectsFile(m_projectsFile);
		if (projectsFile.isOpen()) {
			json data;
			int idx = 0;
			for (auto project : m_projects) {
				data["projects"][idx]["name"] = project->getName();
				data["projects"][idx]["dir"] = project->getDirectory().getPath();
			}
			projectsFile.setData(data);
		}
	}

	auto& getProjects() {
		return m_projects;
	}

	Project* createProject(const std::string& name, const FS::Directory& projectDir) {
		Project* project = new Project(name, projectDir);
		m_projects.push_back(project);
		return project;
	}

	Project* getCurrentProject() {
		return m_currentProject;
	}
private:
	FS::File m_projectsFile;
	Project* m_currentProject = nullptr;
	std::list<Project*> m_projects;

	void createProjectsFile() {
		FS::JsonFileDesc projectsFile(m_projectsFile, std::ios::out);

		if (projectsFile.isOpen()) {
			json data;
			data["projects"] = std::list<json>();
			projectsFile.setData(data);
		}
	}
};

class UserInterface
{
public:
	UserInterface()
	{

	}
};

class Program
{
public:
	Program(HMODULE hModule)
		: m_hModule(hModule)
	{
		m_dir = FS::File::getModule(hModule).getDirectory();
		m_projectManager = new ProjectManager(FS::File(getProgramDirectory(), "projects.json"));
		m_userInterface = new UserInterface;
	}

	FS::Directory& getProgramDirectory() {
		return m_dir;
	}

	ProjectManager* getProjectManager() {
		return m_projectManager;
	}
private:
	HMODULE m_hModule;
	FS::Directory m_dir;
	ProjectManager* m_projectManager;
	UserInterface* m_userInterface;
};

extern Program* g_program;