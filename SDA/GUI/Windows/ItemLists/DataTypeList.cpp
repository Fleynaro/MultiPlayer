#include "DataTypeList.h"
#include "GUI/ClassEditor.h"

struct TestStructA
{
	int a = 5;
	int b = 1001;
	float pos[3] = { 5.0, 1.0, 2.0 };
	double c = 1222.123;
	const char* str = "hello, world!";
};

struct TestStructB
{
	TestStructA* s = new TestStructA;
	int r = 1000;
	TestStructA bbb;
};

TestStructB g_struct;


void GUI::Widget::DataTypeList::ListView::TypeItem::openControlPanel() {
	if (m_type->getType()->getGroup() != Type::Type::Class)
		return;

	Widget::ClassEditor* classEditor = new Widget::ClassEditor;
	classEditor->setView(
		new Widget::ClassEditor::ClassView(
			new Widget::ClassEditor::ClassHierarchy(classEditor, static_cast<API::Type::Class*>(m_type), &g_struct
			)
		)
	);
	getWindow()->addWindow(new Window::ClassEditor(classEditor));
}
