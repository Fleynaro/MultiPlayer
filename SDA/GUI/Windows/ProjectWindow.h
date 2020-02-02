#pragma once
#include "Shared/GUI/Items/IWindow.h"
#include <Project.h>

namespace GUI::Window
{
	class ProjectWindow : public IWindow
	{
	public:
		ProjectWindow(Project* project);

		Project* getProject() {
			return m_project;
		}
	private:
		Project* m_project;
	};
};