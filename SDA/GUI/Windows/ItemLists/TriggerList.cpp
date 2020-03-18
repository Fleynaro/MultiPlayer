#include "TriggerList.h"

void GUI::Window::FunctionTrigger::TriggerEditor::loadSelectedFunctions() {
	for (auto hook : getTrigger()->getHooks()) {
		auto func = getProject()->getProgramExe()->getFunctionManager()->getFunctionById(hook->getFunctionDef()->getId());
		if(func != nullptr)
			m_funcInput->getSelectedFunctions().push_back(func);
	}
}
