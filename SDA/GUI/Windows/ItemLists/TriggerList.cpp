#include "TriggerList.h"

void GUI::Window::FunctionTrigger::TriggerEditor::loadSelectedFunctions() {
	for (auto it : getTrigger()->getFunctions()) {
		m_funcInput->getSelectedFunctions().push_back(it);
	}
}
