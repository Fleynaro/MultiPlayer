#include "Signature.h"
#include "GUI/Windows/ItemLists/FunctionTagList.h"

void GUI::Units::FuncInfo::buildDescription() {
	addItem(m_tagShortCut = new GUI::Widget::FunctionTagShortCut(m_function));
	DeclInfo::buildDescription();
}
