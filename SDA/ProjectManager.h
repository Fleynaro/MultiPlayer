#pragma once
#include <Project.h>
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