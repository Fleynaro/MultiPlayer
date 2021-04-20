#pragma once
#include <GUI.h>

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
			if (m_btn.present()) {
				m_btn.show();
			}
		}
	};
};