#pragma once
#include "resource.h"

#include <GUI.h>

namespace GUI {
	class GuiDemoWindow : public Window
	{
		class ChildWindow : public Window {
		public:
			ChildWindow()
				: Window("Child window")
			{}

			void renderWindow() override {
				Text::Text("Here text").show();
			}
		};


		Button::StdButton m_btn;
		ChildWindow* m_childWindow;
	public:
		GuiDemoWindow()
			: Window("GUI Demo")
		{
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_MenuBar);
			setFullscreen(true);

			m_btn = Button::StdButton("oks");
			m_childWindow = new ChildWindow;
		}

		void renderWindow() override {
			if (m_childWindow) {
				m_childWindow->show();
				if (m_childWindow->isClosed()) {
					delete m_childWindow;
					m_childWindow = nullptr;
				}
			}

			if (m_btn.present()) {
				m_btn.show();
			}
		}
	};
};