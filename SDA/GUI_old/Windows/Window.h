#pragma once
#include "Shared/GUI/Items/IWindow.h"
#include <Project.h>

namespace GUI::Window
{
	class PrjWindow : public IWindow
	{
	public:
		PrjWindow(const std::string name)
			: IWindow(name)
		{}

		void addWindow(PrjWindow* window) {
			IWindow::addWindow(window);
			window->setProject(m_project);
		}

		void setProject(Project* project) {
			m_project = project;
		}

		Project* getProject() {
			return m_project;
		}
	private:
		Project* m_project;
	};

	//class PrjWidget : public Container
	//{
	//public:
	//	PrjWindow* getWindow() {
	//		return 
	//	}
	//};
};