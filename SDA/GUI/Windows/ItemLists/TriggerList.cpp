#include "TriggerList.h"
#include "GUI/TriggerTableView.h"

void GUI::Window::FunctionTrigger::TriggerEditor::loadSelectedFunctions() {
	for (auto it : getTrigger()->getFunctions()) {
		m_funcInput->getSelectedFunctions().push_back(it);
	}
}

void GUI::Window::FunctionTrigger::TriggerEditor::buildTableLog() {
	m_tableLogContainer->clear();
	if (getTrigger()->getTableLog() == nullptr)
		return;

	Elements::Generic::Checkbox* cb_collecting;
	(*m_tableLogContainer)
		.newLine()
		.addItem(cb_collecting = new Elements::Generic::Checkbox("Collecting enabled", getTrigger()->getTableLog()->m_enabled,
			Events::Listener(
				std::function([=](Events::ISender* sender) {
					getTrigger()->getTableLog()->m_enabled = cb_collecting->isSelected();
				})
			)
		))
		.sameLine().addItem(
			new Elements::Button::ButtonStd(
				"Clear all",
				Events::Listener(
					std::function([=](Events::ISender* sender) {
						getTrigger()->getTableLog()->clear();
					})
				)
			)
		)
		.addItem(new Widget::TableViews::TriggerTableView(getTrigger()->getTableLog(), getProject()))
		.newLine()
		.newLine();
}
