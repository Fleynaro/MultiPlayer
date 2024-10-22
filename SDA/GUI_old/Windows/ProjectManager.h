#pragma once
#include "Shared/GUI/Items/IWindow.h"
#include <ProjectManager.h>
#include "GUI/Windows/ProjectWindow.h"

namespace GUI::Window
{
	class ProjectCreating : public IWindow
	{
	public:
		::ProjectManager* m_projectManager;
		GUI::Elements::Input::Text* m_projectNameText = nullptr;
		GUI::Elements::Input::Text* m_projectDirText = nullptr;
		bool m_projectDirChangedByUser = false;

		ProjectCreating(::ProjectManager* projectManager, const std::string& prjName = "MyProject")
			: IWindow("Create a project"), m_projectManager(projectManager)
		{
			setWidth(350);
			setHeight(150);
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			getMainContainer()
				.text("Enter your project name:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input1",
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								if(!m_projectDirChangedByUser) {
									m_projectDirText->setInputValue(
										FS::Directory(m_projectDirText->getInputValue()).back().next(m_projectNameText->getInputValue()).getPath()
									);
								}
							})
						)
					)),
					(Item**)& m_projectNameText
				)
				.text("Enter your project location:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input2",
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								m_projectDirChangedByUser = true;
							})
						)
					)),
					(Item**)& m_projectDirText
				)
				.newLine()
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"Create",
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								createProject();
							})
						)
					)
				);

			m_projectNameText->setInputValue(prjName);
			m_projectDirText->setInputValue(m_projectManager->getDefaultDirectory().next(prjName).getPath());
		}

		void createProject();
	};

	class ProjectManagerWin : public IWindow
	{
	public:
		Elements::Text::Text* m_selectedProjectInfoText = nullptr;
		Elements::List::ListBoxDyn* m_projectsList = nullptr;
		Container* m_projectListBlock = nullptr;
		Container* m_noOneProjectCreated = nullptr;
		::ProjectManager* m_projectManager;

		ProjectManagerWin(::ProjectManager* projectManager)
			: IWindow("Project manager"), m_projectManager(projectManager)
		{
			setWidth(550);
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			getMainContainer()
				.beginContainer((Container**)& m_projectListBlock)
					.text("Select project from the list")
					.newLine()
					.addItem
					(
						(new Elements::List::ListBoxDyn("", 0,
							Events::Listener(
								std::function([&](Events::ISender* sender) {
									auto project = (Project*)m_projectsList->getSelectedItemPtr();
									showProjectInfo(project);
								})
							)
						))
						->setWidth(400)
						->setHeight(-1),
						(Item**)& m_projectsList
					)
					.newLine()
					.addItem(
						new GUI::Elements::Button::ButtonStd(
							"open",
							Events::Listener(
								std::function([&](Events::ISender* sender) {
									if (m_projectManager->isAnyProjectActive())
										return;

									auto project = (Project*)m_projectsList->getSelectedItemPtr();
									project->open();
									m_projectManager->setCurrentProject(project);

									getParent()->addWindow(
										new Window::ProjectWindow(project)
									);
									close();
								})
							)
						)
					)
					.newLine()
					.text("", (Elements::Text::Text**)& m_selectedProjectInfoText)
					.newLine()
				.end()
				.beginContainer((Container**)& m_noOneProjectCreated)
					.text("<No project has been created yet.>")
					.newLine()
				.end()
				.text("You can create a new project")
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"create a project",
						Events::Listener(
							std::function([&](Events::ISender* sender) {
								addWindow(new ProjectCreating(m_projectManager));
							})
						)
					)
				);
			updateProjectList();
		}

		void showProjectInfo(Project* project) {
			m_selectedProjectInfoText->setText(
				"Project name: " + project->getName() +
				"\nProject location: " + project->getDirectory().getPath());
		}

		void updateProjectList() {
			m_projectsList->clear();
			for (auto& project : m_projectManager->getProjects()) {
				m_projectsList->addItem(project->getName(), project);
			}

			bool hasProject = !m_projectManager->getProjects().empty();
			m_projectListBlock->setDisplay(hasProject);
			m_noOneProjectCreated->setDisplay(!hasProject);

			if (hasProject) {
				showProjectInfo(*m_projectManager->getProjects().begin());
			}
		}
	};
};