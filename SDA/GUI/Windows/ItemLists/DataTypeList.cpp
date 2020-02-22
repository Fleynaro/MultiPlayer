#include "DataTypeList.h"
#include "GUI/ClassEditor.h"

void GUI::Widget::DataTypeList::ListView::TypeItem::openControlPanel() {
	if (m_type->getType()->getGroup() != Type::Type::Class)
		return;

	Widget::ClassEditor* classEditor = new Widget::ClassEditor;
	classEditor->setView(
		new Widget::ClassEditor::ClassView(
			new Widget::ClassEditor::ClassHierarchy(classEditor, static_cast<API::Type::Class*>(m_type), GetModuleHandle(NULL)
			)
		)
	);
	getWindow()->addWindow(new Window::ClassEditor(classEditor));
}
