#pragma once
#include "GUI/Items/IWindow.h"

using namespace GUI::Window;

class PhysicControl : public IWindow
{
public:
	PhysicControl()
		: IWindow("Physic control window")
	{
		setWidth(400);
		setHeight(200);

		getMainContainer()
			.addItem(
				new GUI::Elements::Input::Float(
					"Enter speed",
					new GUI::Events::EventUI(
						EVENT_LAMBDA(info) {
							
						}
					)
				)
			);
	}
};