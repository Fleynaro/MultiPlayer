#pragma once
#include "GUI/Items/IWindow.h"
#include <ProjectManager.h>

namespace GUI::Window
{
class ProjectCreating : public IWindow
{
	public:
		ProjectCreating()
			: IWindow("Create a project")
		{
			setWidth(350);
			setHeight(130);

			getMainContainer()
				.text("Enter your project name:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input1",
						50,
						new Events::EventUI(EVENT_LAMBDA(info) {

						})
					))
					->setInputValue("lol")
				)
				.text("Enter your project location:")
				.addItem(
					(new GUI::Elements::Input::Text(
						"##input2",
						150,
						new Events::EventUI(EVENT_LAMBDA(info) {

						})
					))
					->setInputValue("lol")
				);
		}
	};

	class ProjectManager : public IWindow
	{
	public:
		Elements::List::ListBoxDyn* m_projectsList = nullptr;
		Container* m_projectListBlock = nullptr;
		Container* m_noOneProjectCreated = nullptr;

		ProjectManager()
			: IWindow("Project manager")
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

						})
					)
				);

			m_projectsList->addItem("MyProject1", nullptr);
			m_projectsList->addItem("MyProject2", nullptr);
			m_projectListBlock->setDisplay(true);
			m_noOneProjectCreated->setDisplay(false);
		}
	};
};