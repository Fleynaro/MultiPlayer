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
		m_dataTypeList = new Window::DataTypeList
	);
	m_dataTypeList->getList()->setView(
		new Widget::DataTypeList::ListView(m_dataTypeList, getProject()->getProgramExe()->getTypeManager())
	);

	addWindow(
		m_funcSelList = new Window::FunctionList(new Widget::FuncSelectList(
			new Events::EventUI(EVENT_LAMBDA(info) {
				auto list = m_funcSelList->getList()->getSelectedFunctions();
				list.size();
				m_funcSelList->close();
			})
		))
	);
	m_funcSelList->getList()->setView(
		new Widget::FuncSelectList::ListView(m_funcSelList->getList(), getProject()->getProgramExe()->getFunctionManager())
	);
}
