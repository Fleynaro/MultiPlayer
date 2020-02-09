#include "FunctionCP.h"
#include "GUI/Windows/ItemLists/FunctionList.h"

using namespace GUI::Widget;
using namespace GUI::Window;

void FunctionCP::onVisibleOn() {
	getSideBar()->addMenuItem("Generic", m_generic = new Container);
	getSideBar()->addMenuItem("Call", m_callFunction = new Container);
	getSideBar()->addMenuItem("Call stack", m_funcCallStackViewer = new FunctionCallStackViewer(m_function));
	getSideBar()->setSelectedContainer(m_generic);

	buildGeneric();
	buildCallFunction();

	(*m_generic)
		.newLine()
		.addItem(new Units::FuncInfo(m_function, true));
}
