#include "ProjectWindow.h"
#include "GUI/Windows/ItemLists/DataTypeList.h"
#include "GUI/Windows/ItemLists/FunctionList.h"

using namespace GUI::Window;

ProjectWindow::ProjectWindow(Project* project)
	: m_project(project), IWindow("Project: " + project->getName())
{
	setWidth(1000);
	setHeight(600);

	addWindow(
		new Window::DataTypeList(
			getProject()->getProgramExe()->getTypeManager())
	);


	addWindow(
		m_funcSelList = new Window::FuncSelectList(
			getProject()->getProgramExe()->getFunctionManager(),
			new Events::EventUI(EVENT_LAMBDA(info) {
				auto list = m_funcSelList->getSelectedFunctions();
				list.size();
				m_funcSelList->close();
			})
		)
	);
}
