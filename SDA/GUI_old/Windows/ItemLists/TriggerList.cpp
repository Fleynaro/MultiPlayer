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

	auto tableView = new Widget::TableViews::TriggerTableView(getTrigger()->getTableLog(), getProject());
	(*m_tableLogContainer)
		.newLine()
		.addItem(new Elements::Generic::Checkbox("Collecting enabled", getTrigger()->getTableLog()->m_enabled,
			Events::Listener(
				std::function([&](Events::ISender* sender) {
					auto cb_collecting = static_cast<Elements::Generic::Checkbox*>(sender);
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
						tableView->update();
					})
				)
			)
		)
		.addItem(tableView)
		.newLine()
		.newLine();
}
