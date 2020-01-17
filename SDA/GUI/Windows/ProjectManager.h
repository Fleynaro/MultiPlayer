#pragma once
#include "GUI/Items/IWindow.h"
#include <ProjectManager.h>

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

			getMainContainer()
				.text("Enter your project name:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input1",
						50,
						new Events::EventUI(EVENT_LAMBDA(info) {
							if(!m_projectDirChangedByUser) {
								m_projectDirText->setInputValue(
									FS::Directory(m_projectDirText->getInputValue()).back().next(m_projectNameText->getInputValue()).getPath()
								);
							}
						})
					)),
					(Item**)& m_projectNameText
				)
				.text("Enter your project location:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input2",
						150,
						new Events::EventUI(EVENT_LAMBDA(info) {
							m_projectDirChangedByUser = true;
						})
					)),
					(Item**)& m_projectDirText
				)
				.newLine()
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"Create",
						new Events::EventUI(EVENT_METHOD_PASS(createProject))
					)
				);

			m_projectNameText->setInputValue(prjName);
			m_projectDirText->setInputValue(m_projectManager->getDefaultDirectory().next(prjName).getPath());
		}

		void CALLBACK_createProject(const GUI::Events::EventInfo::Type& info);
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
			setWidth(400);
			setHeight(200);

			getMainContainer()
				.beginContainer((Container**)& m_projectListBlock)
					.text("Select project from the list")
					.newLine()
					.addItem
					(
						(new Elements::List::ListBoxDyn("", 0,
							new Events::EventUI(EVENT_LAMBDA(info) {
								auto project = (Project*)m_projectsList->getSelectedItemPtr();
								showProjectInfo(project);
							})
						))
						->setWidth(400)
						->setHeight(-1),
						(Item**)& m_projectsList
					)
					.newLine()
					.addItem(
						new GUI::Elements::Button::ButtonStd(
							"open",
							new Events::EventUI(EVENT_LAMBDA(info) {
								auto project = (Project*)m_projectsList->getSelectedItemPtr();
								project->load();

								close();
							})
						)
					)
					.newLine()
					.text("", (Elements::Text::Text**)& m_selectedProjectInfoText)
					.newLine()
				.end()
				.beginContainer((Container**)& m_noOneProjectCreated)
					.text("No project has been created yet.")
					.newLine()
				.end()
				.text("You can create a new project")
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"create a project",
						new Events::EventUI(EVENT_LAMBDA(info) {
							addWindow(new ProjectCreating(m_projectManager));
						})
					)
				);
			updateProjectList();
		}

		void showProjectInfo(Project* project) {
			m_selectedProjectInfoText->setText("Project name: " + project->getName() + "\nProject location: " + project->getDirectory().getPath());
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