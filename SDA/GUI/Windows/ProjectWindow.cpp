#include "ProjectWindow.h"
#include "GUI/Windows/ItemLists/DataTypeList.h"
#include "GUI/Windows/ItemLists/FunctionList.h"

using namespace GUI::Window;

ProjectWindow::ProjectWindow(Project* project)
	: m_project(project), IWindow("Project: " + project->getName())
{
	setWidth(1000);
	setHeight(600);

	auto dataTypeListWidget = new Widget::DataTypeList;
	dataTypeListWidget->setView(
		new Widget::DataTypeList::ListView(dataTypeListWidget, getProject()->getProgramExe()->getTypeManager())
	);
	addWindow(
		m_dataTypeList = new Window::DataTypeList
	);

	auto functionListWidget = new Widget::FuncSelectList(
		new Events::EventUI(EVENT_LAMBDA(info) {
			auto list = static_cast<Widget::FuncSelectList*>(m_funcSelList->getList())->getSelectedFunctions();
			list.size();
			m_funcSelList->close();
		})
	);
	functionListWidget->setView(
		new Widget::FuncSelectList::ListView(functionListWidget, getProject()->getProgramExe()->getFunctionManager())
	);
	addWindow(
		m_funcSelList = new Window::FunctionList(functionListWidget)
	);
}
