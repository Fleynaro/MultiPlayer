#pragma once
#include "GUI/Items/IWindow.h"
#include <Program.h>

namespace GUI::Window
{
	class ProjectCreating : public IWindow
	{
	public:
		::ProjectManager* m_projectManager;
		std::string m_projectName;
		std::string m_projectDir;

		ProjectCreating(::ProjectManager* projectManager)
			: IWindow("Create a project"), m_projectManager(projectManager)
		{
			setWidth(350);
			setHeight(130);

			m_projectName = "MyProject";
			m_projectDir = m_projectManager->getDefaultDirectory().next("MyProject").getPath();

			getMainContainer()
				.text("Enter your project name:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input1",
						50,
						new Events::EventUI(EVENT_LAMBDA(info) {
							
						})
					))
					->setInputValue(m_projectName)
				)
				.text("Enter your project location:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input2",
						150,
						new Events::EventUI(EVENT_LAMBDA(info) {

						})
					))
					->setInputValue(m_projectDir)
				)
				.newLine()
				.addItem(
					new GUI::Elements::Button::ButtonStd(
						"Create",
						new Events::EventUI(EVENT_LAMBDA(info) {
							
						})
					)
				);
		}
	};

	class ProjectManager : public IWindow
	{
	public:
		Elements::List::ListBoxDyn* m_projectsList = nullptr;
		Container* m_projectListBlock = nullptr;
		Container* m_noOneProjectCreated = nullptr;
		::ProjectManager* m_projectManager;

		ProjectManager(::ProjectManager* projectManager)
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
								//info->getSender()
							})
						))
						->setWidth(400)
						->setHeight(-1),
						(Item**)& m_projectsList
					)
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

			for(auto& project : m_projectManager->getProjects()) {
				m_projectsList->addItem(project->getName(), project);
			}

			bool hasProject = !m_projectManager->getProjects().empty();
			m_projectListBlock->setDisplay(hasProject);
			m_noOneProjectCreated->setDisplay(!hasProject);
		}
	};
};