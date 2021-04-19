#pragma once
#include "GUI.h"

namespace GUI {
	class DecompilerDemoWindow : public Window
	{
		Button::StdButton m_btn;
	public:
		DecompilerDemoWindow()
			: Window("Decompiler")
		{
			m_btn = Button::StdButton("ok");
		}

		void renderWindow() override {
			m_btn.show();
			if (m_btn.isClicked()) {
				m_btn.show();
			}
		}
	};
};