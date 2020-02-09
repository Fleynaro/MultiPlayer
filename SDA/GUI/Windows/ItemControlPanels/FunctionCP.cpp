#include "FunctionCP.h"
#include "GUI/Windows/ItemLists/FunctionList.h"

using namespace GUI::Widget;
using namespace GUI::Window;

void FunctionCP::onVisibleOn() {
	getSideBar()->addMenuItem("Generic", m_generic = new Container);
	getSideBar()->addMenuItem("Call", m_callFunction = new Container);
	getSideBar()->addMenuItem("Call stack", (m_callStackViewer = new FunctionList)->getMainContainerPtr());
	getSideBar()->setSelectedContainer(m_generic);

	m_callStackViewer->setView(new FunctionList::CallStackView(m_callStackViewer, m_function));
	m_callStackViewer->update();

	buildGeneric();
	buildCallFunction();

	(*m_generic)
		.newLine()
		.addItem(new Units::FuncInfo(m_function, true));
}
