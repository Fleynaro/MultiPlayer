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
				new Events::EventUI(EVENT_LAMBDA(info) {
					rebuild();
				})
			)
		)
		.newLine();
}
