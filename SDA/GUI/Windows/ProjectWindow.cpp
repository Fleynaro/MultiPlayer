#include "ProjectWindow.h"
#include "GUI/Windows/ItemLists/DataTypeList.h"
#include "GUI/Windows/ItemLists/FunctionList.h"
#include "GUI/Windows/ItemLists/FunctionTagList.h"
#include "GUI/Windows/ItemLists/TriggerList.h"

using namespace GUI::Window;

ProjectWindow::ProjectWindow(Project* project)
	: m_project(project), PrjWindow("Project: " + project->getName())
{
	setWidth(1000);
	setHeight(600);
	setProject(project);

	auto dataTypeListWidget = new Widget::DataTypeList;
	dataTypeListWidget->setView(
		new Widget::DataTypeList::ListView(dataTypeListWidget, getProject()->getProgramExe()->getTypeManager())
	);
	IWindow::addWindow(
		m_dataTypeList = new Window::DataTypeList(dataTypeListWidget)
	);

	auto functionListWidget = new Widget::FuncSelectList(
		new Widget::FunctionList,
		Events::Listener(
			std::function([&](Events::ISender* sender) {
				auto list = static_cast<Widget::FuncSelectList*>(m_funcSelList->getList())->getSelectedItems();
				static_cast<int>(list.size());
				m_funcSelList->close();
			})
		)
	);
	functionListWidget->setView(
		new Widget::FuncSelectList::ListView(functionListWidget, getProject()->getProgramExe()->getFunctionManager()),
		false
	);
	IWindow::addWindow(
		m_funcSelList = new Window::FunctionList(functionListWidget)
	);
	functionListWidget->update();

	auto funcManager = getProject()->getProgramExe()->getFunctionManager();
	auto tagManager = funcManager->getFunctionTagManager();
	auto tag1 = tagManager->createTag(tagManager->m_getTag, "test tag1");
	auto ftag1 = tagManager->createTag(funcManager->getFunctionDeclById(12), tag1, "test ftag1");
	auto ftag2 = tagManager->createTag(funcManager->getFunctionDeclById(12), tagManager->m_setTag, "test ftag2");
	tagManager->calculateAllTags();


	auto triggerManager = getProject()->getProgramExe()->getTriggerManager();
	{
		auto trigger = triggerManager->createFunctionTrigger("myTrigger1", "for test, no more");
		trigger->getFilters()->addFilter(new Trigger::Function::Filter::Cmp::Argument(1, 1, Trigger::Function::Filter::Cmp::Eq));
		trigger->getFilters()->addFilter(new Trigger::Function::Filter::Cmp::RetValue(100, Trigger::Function::Filter::Cmp::Ge));
	}
	{
		auto trigger = triggerManager->createFunctionTrigger("global", "for testing, no more");
		auto win = new Window::FunctionTrigger::TriggerEditor(trigger, funcManager);
		addWindow(win);
	}

	getMainContainer()
		.addItem(new Widget::FunctionInput(funcManager))
		.newLine()
		.addItem(new Widget::FunctionTagInput(tagManager))
		.newLine()
		.addItem(new Widget::TriggerInput(triggerManager))
		.newLine()
		.newLine()
		.text("Base: 0x" + Generic::String::NumberToHex((uint64_t)GetModuleHandle(NULL)));


}
