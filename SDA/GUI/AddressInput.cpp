#include "AddressInput.h"
#include "Windows/ItemLists/DataTypeList.h"

using namespace CE;
using namespace GUI;


void AddressValueEditor::buildTypeSelector() {
	(*this)
		.text("Type is not selected.")
		.addItem(
			new Elements::Button::ButtonStd(
				"Select type",
				Events::Listener(
					std::function([&](Events::ISender* sender) {
						if (m_typeManager == nullptr)
							return;
						auto dataTypeSelector = new Window::DataTypeSelector(m_typeManager);
						getWindow()->addWindow(dataTypeSelector);
						dataTypeSelector->setType(m_type);

						dataTypeSelector->getCloseEvent() +=
							[=](Events::ISender* sender) {
								if (dataTypeSelector->getType() != nullptr) {
									setType(dataTypeSelector->getType());
									rebuild();
								}
							};
					})
				)
			)
		)
		.newLine();
}
