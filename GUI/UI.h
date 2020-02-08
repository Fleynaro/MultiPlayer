#pragma once

#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"
#include "TestWindows.h"

using namespace GUI::Window;
using namespace GUI::Widget;

class UI
{
public:
	UI() {
	
	}

	class PopupContainer
		: public Container,
		private Events::OnHovered<PopupContainer>
	{
	public:
		PopupContainer(bool display = false, int maxTimeWaitToHideMs = 1000)
			: m_display(display), m_maxTimeWaitToHideMs(maxTimeWaitToHideMs)
		{}

		bool isShown() override {
			if (m_lastHoveredOut != 0 &&
				GetTickCount64() - m_lastHoveredOut >= m_maxTimeWaitToHideMs) {
				m_display = false;
				ImGui::CloseCurrentPopup();
			}

			return m_display;
		}

		void render() override {
			if (ImGui::BeginPopup(getUniqueId().c_str()))
			{
				Container::render();
				//sendHoveredEvent();
				ImGui::EndPopup();
			}
		}

		void setActive() {
			m_display = true;
			m_lastHoveredOut = 0;
			ImGui::OpenPopup(getUniqueId().c_str());
		}
	protected:
		void onHoveredOut() override {
			m_lastHoveredOut = GetTickCount64();
		}
	private:
		bool m_display = false;
		int m_maxTimeWaitToHideMs;
		ULONGLONG m_lastHoveredOut = 0;
	};

	class ShortCut
		: public PopupContainer
	{
	public:
		ShortCut()
			: PopupContainer(false, 100)
		{
			
			text("hello!");
			newLine();
			text("i am a cool");
			newLine();
			text("i am a cool");
			newLine();
			text("i am a cool");
		}
	};

	class HoverText
		: public Elements::Text::Text,
		public Events::ISender,
		public Events::OnHovered<HoverText>
	{
	public:
		ShortCut* m_cont;
		HoverText(const std::string& name)
			: Elements::Text::Text(name)
		{
			m_cont = new ShortCut;
		}

		void render() override {
			Elements::Text::Text::render();
			sendHoveredEvent();

			m_cont->show();
		}

		void onHoveredIn() {
			m_cont->setActive();
		}
	};







	class WindowTest : public IWindow
	{
	public:
		//bool m_selected
		
		WindowTest()
			: IWindow("ImGui window for test")
		{
			getMainContainer()
				.addItem(new HoverText("text"))
				.beginChild()
					.setWidth(500)
					.setHeight(300)

					.beginTable()
						.setBorder(true)

						.beginHeader()
							.beginTD()
								.setWidth(100.f)
								.text("col 1")
							.endTD()

							.beginTD()
								.setWidth(80.f)
								.text("col 2")
							.endTD()

							.beginTD()
								.setWidth(200.f)
								.text("col 3")
							.endTD()
						.endHeader()

						.beginBody()
							.beginTR()
								.beginTD()
									.text("1 1")
								.endTD()

								.beginTD()
									.text("1 2")
								.endTD()

								.beginTD()
									.text("1 3")
								.endTD()
							.endTR()

							.beginTR()
								.beginTD()
									.text("2 1")
								.endTD()

								.beginTD()
									.text("2 2")
								.endTD()

								.beginTD()
									.text("2 3")
								.endTD()
							.endTR()
						.endBody()
					.end()
				.end()
				.beginImGui([]() {
					/*ImGui::Begin("Issue #1453");
					ImGui::BeginChild("test", ImVec2(100, 100));
					ImGui::OpenPopup("lol");
					if (ImGui::BeginPopupContextWindow("lol"))
					{
						if (ImGui::TreeNode("Base"))
						{
							ImGui::Indent();
							ImGui::Text("Num Slots");
							ImGui::Text("Count");
							ImGui::Unindent();
							ImGui::TreePop();
						}
						ImGui::EndPopup();
					}
					ImGui::EndChild();
					ImGui::End();*/

					/*const char* items[] = { "AAAA", "BBBB", "CCCC", "DDDD", "EEEE", "FFFF", "GGGG", "HHHH", "IIII", "JJJJ", "KKKK", "LLLLLLL", "MMMM", "OOOOOOO", "PPPP", "QQQQQQQQQQ", "RRR", "SSSS" };
					static const char* current_item = NULL;
					ImGuiComboFlags flags = ImGuiComboFlags_NoArrowButton;

					ImGuiStyle& style = ImGui::GetStyle();
					float w = ImGui::CalcItemWidth();
					float spacing = style.ItemInnerSpacing.x;
					float button_sz = ImGui::GetFrameHeight();
					ImGui::PushItemWidth(w - spacing * 2.0f - button_sz * 2.0f);
					if (ImGui::BeginCombo("##custom combo", current_item, ImGuiComboFlags_NoArrowButton))
					{
						for (int n = 0; n < IM_ARRAYSIZE(items); n++)
						{
							bool is_selected = (current_item == items[n]);
							if (ImGui::Selectable(items[n], is_selected))
								current_item = items[n];
							if (is_selected)
								ImGui::SetItemDefaultFocus();
						}
						ImGui::EndCombo();
					}
					ImGui::PopItemWidth();
					ImGui::SameLine(0, spacing);
					if (ImGui::ArrowButton("##r", ImGuiDir_Left))
					{
					}
					ImGui::SameLine(0, spacing);
					if (ImGui::ArrowButton("##r", ImGuiDir_Right))
					{
					}
					ImGui::SameLine(0, style.ItemInnerSpacing.x);
					ImGui::Text("Custom Combo");*/

					static char input[32]{ "" };
					ImGui::InputText("##input", input, sizeof(input));
					ImGui::SameLine();
					static bool isOpen = false;
					bool isFocused = ImGui::IsItemFocused();
					isOpen |= ImGui::IsItemActive();
					if (isOpen)
					{
						ImGui::SetNextWindowPos({ ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y });
						ImGui::SetNextWindowSize({ ImGui::GetItemRectSize().x, 0 });
						if (ImGui::Begin("##popup", &isOpen, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
						{
							isFocused |= ImGui::IsWindowFocused();
							static const char* autocomplete[] = { "cats", "dogs", "rabbits", "turtles" };
							for (int i = 0; i < IM_ARRAYSIZE(autocomplete); i++)
							{
								if (strstr(autocomplete[i], input) == NULL)
									continue;
								if (ImGui::Selectable(autocomplete[i]) || (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter)))
								{
									strcpy_s(input, autocomplete[i]);
									isOpen = false;
								}
							}
							ImGui::End();
						}
						isOpen &= isFocused;
					}
				});
		}
	};

	class WinManager
	{
	public:
		static void registerWindows() {
			UI::WinManager::addWindow(new WindowTest);
		}

		static void addWindow(GUI::Window::IWindow* window) {
			window->setCloseEvent(
				new GUI::Events::EventUI(
					S_EVENT_LAMBDA(info) {
						auto win = (GUI::Window::IWindow*)info->getSender();
						removeWindow(win);
						delete win;
					}
				)
			);
			m_windows.push_back(window);
		}

		static void removeWindow(GUI::Window::IWindow* window) {
			m_windows.remove(window);
			if (m_windows.size() == 0) {
				setVisibleForAll(false);
			}
		}

		static void setVisibleForAll(bool state) {
			m_shown = state;
		}

		static bool isVisible() {
			return m_shown;
		}

		static void RenderAllWindows() {
			if (!m_shown)
				return;
			for (auto it : m_windows) {
				it->show();
			}
		}
	private:
		inline static std::list<GUI::Window::IWindow*> m_windows;
		inline static bool m_shown = true;
	};

	void init(void* hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx)
	{
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui_ImplWin32_Init(hwnd);
		ImGui_ImplDX11_Init(device, ctx);
		ImGui::StyleColorsDark();
		//GUI::Font::init();
		GUI::StyleThemes::Standart();
	}

	void render()
	{
		if (!WinManager::isVisible())
			return;

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		//ImGui::PushFont(GUI::Font::Tahoma);
		WinManager::RenderAllWindows();
		GUI::Events::EventUI::handleEvents();
		//ImGui::PopFont();

		ImGui::Render();
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	}
};