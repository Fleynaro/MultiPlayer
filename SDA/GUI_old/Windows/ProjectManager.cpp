#include "ProjectManager.h"


void GUI::Window::ProjectCreating::createProject()
{
	auto projectDir = FS::Directory(m_projectDirText->getInputValue());
	if (projectDir.back().exists() && !ProjectManager::doesProjectExists(projectDir))
	{
		projectDir.createIfNotExists();
		auto project = m_projectManager->createProject(m_projectNameText->getInputValue(), projectDir);
		m_projectManager->saveProjects();
		project->create();
		m_projectManager->setCurrentProject(project);
		static_cast<ProjectManagerWin*>(getParent())->updateProjectList();
		close();
	}
}
