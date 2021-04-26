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
			setFlags(ImGuiWindowFlags_MenuBar);
			setFullscreen(true);

			m_btn = Button::StdButton("oks");
			m_childWindow = new ChildWindow;
		}

	protected:
		void renderWindow() override {
			renderChildWindows();

			renderMenu();

			renderTableSample();

			if (ImGui::BeginChild("left pane", ImVec2(0, 0), true)) {

				ImGui::EndChild();
			}


			if (m_btn.present()) {
			}
			Button::StdButton("context menu").show();
			ImGui::OpenPopupOnItemClick("context");

			if (ImGui::BeginPopup("context"))
			{
				if (ImGui::MenuItem("Remove one")) {
				}
				if (ImGui::MenuItem("Remove all")) {
				}
				ImGui::EndPopup();
			}
		}

		void renderMenu() {
			if (ImGui::BeginMenuBar())
			{
				if (ImGui::BeginMenu("File"))
				{
					if (ImGui::MenuItem("item 1", "", true)) {
					}
						
					if (ImGui::MenuItem("item 2", "Alt+F4")) {
					}

					ImGui::EndMenu();
				}

				ImGui::EndMenuBar();
			}
		}

		void renderTableSample() {
			if (ImGui::BeginTable("##table1", 3, ImGuiTableFlags_Borders))
			{
				for (int row = 0; row < 4; row++)
				{
					ImGui::TableNextRow();
					for (int column = 0; column < 3; column++)
					{
						ImGui::TableSetColumnIndex(column);
						ImGui::Text("Row %d Column %d", row, column);
					}
				}
				ImGui::EndTable();
			}
		}

		void renderChildWindows() {
			if (m_childWindow) {
				m_childWindow->show();
				if (m_childWindow->isClosed()) {
					delete m_childWindow;
					m_childWindow = nullptr;
				}
			}
		}
	};
};