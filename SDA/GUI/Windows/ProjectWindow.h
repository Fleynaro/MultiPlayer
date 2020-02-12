#pragma once
#include "Shared/GUI/Items/IWindow.h"
#include <Project.h>

namespace GUI::Window
{
	class DataTypeList;
	class FunctionList;

	class ProjectWindow : public IWindow
	{
	public:
		ProjectWindow(Project* project);

		Project* getProject() {
			return m_project;
		}
	private:
		Project* m_project;
		Window::FunctionList* m_funcSelList = nullptr;
		Window::DataTypeList* m_dataTypeList = nullptr;
	};
};