#pragma once
#include <GUI/Windows/Window.h>

namespace GUI::Window
{
	class DataTypeList;
	class FunctionList;
	class FunctionTagList;

	class ProjectWindow : public PrjWindow
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
		Window::FunctionTagList* m_funcTagList = nullptr;
	};
};