#include "ProjectWindow.h"
#include "GUI/Windows/ItemLists/DataTypeList.h"
#include "GUI/Windows/ItemLists/FunctionList.h"
#include "GUI/Windows/ItemLists/FunctionTagList.h"

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
		m_dataTypeList = new Window::DataTypeList(dataTypeListWidget)
	);

	auto functionListWidget = new Widget::FuncSelectList(
		new Widget::FunctionList,
		new Events::EventUI(EVENT_LAMBDA(info) {
			auto list = static_cast<Widget::FuncSelectList*>(m_funcSelList->getList())->getSelectedItems();
			list.size();
			m_funcSelList->close();
		})
	);
	functionListWidget->setView(
		new Widget::FuncSelectList::ListView(functionListWidget, getProject()->getProgramExe()->getFunctionManager()),
		false
	);
	addWindow(
		m_funcSelList = new Window::FunctionList(functionListWidget)
	);
	functionListWidget->update();

	auto funcManager = getProject()->getProgramExe()->getFunctionManager();
	auto tagManager = funcManager->getFunctionTagManager();
	auto tag1 = tagManager->createTag(tagManager->m_getTag, "test tag1");
	auto ftag1 = tagManager->createTag(funcManager->getFunctionDeclById(12), tag1, "test ftag1");
	auto ftag2 = tagManager->createTag(funcManager->getFunctionDeclById(12), tagManager->m_setTag, "test ftag2");
	tagManager->calculateAllTags();

	getMainContainer()
		.addItem(new Widget::FunctionInput(funcManager))
		.newLine()
		.addItem(new Widget::FunctionTagInput(tagManager))
		.newLine()
		.newLine()
		.text("Base: 0x" + Generic::String::NumberToHex((uint64_t)GetModuleHandle(NULL)));
}
