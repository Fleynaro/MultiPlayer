#pragma once
#include "resource.h"

#include <GUI.h>

namespace GUI {
	class GuiDemoWindow : public Window
	{
		Button::StdButton m_btn;
	public:
		GuiDemoWindow()
			: Window("GUI Demo")
		{
			m_btn = Button::StdButton("oks");
		}

		void renderWindow() override {
			if (m_btn.present()) {
				m_btn.show();
			}
		}
	};
};