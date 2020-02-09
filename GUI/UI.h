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

	class ShortCut
		: public PopupContainer
	{
	public:
		ShortCut()
			: PopupContainer(false, 0)
		{}

		void onVisibleOn() override {
			/*setWidth(400);

			beginTable()
				.setBorder(false)

				.beginHeader()
					.beginTD()
						.text("col 1").sameText("col 2")
					.endTD()

					.beginTD()
						.text("col 2")
					.endTD()
				.endHeader()

				.beginBody()
					.beginTR()
						.beginTD()
							.text("1 1fsdfsdfs")
						.endTD()

						.beginTD()
							.text("1 2fsdfsdfdsfsfddddddddddddddddddddddd")
						.endTD()
					.endTR()

					.beginTR()
						.beginTD()
							.text("2 1")
						.endTD()

						.beginTD()
							.text("2 2")
						.endTD()
					.endTR()

					.beginTR()
						.beginTD()
							.text("1 1")
						.endTD()

						.beginTD()
							.text("1 2")
						.endTD()
					.endTR()

					.beginTR()
						.beginTD()
							.text("2 1")
						.endTD()

						.beginTD()
							.text("2 2")
						.endTD()
					.endTR()
				.endBody()
			.end();*/

			beginImGui([&] {
				ImGui::Columns(2);
				ImGui::Text("Blah");
				ImGui::NextColumn();
				ImGui::Text("Blah");
				ImGui::Columns(1);
					
				});

	
			
		}

		void onVisibleOff() override {
			clear();
		}

		void render() override {
			PopupContainer::render();

			
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
			: Elements::Text::Text(name), Events::OnHovered<HoverText>(this)
		{
			m_cont = new ShortCut;
		}

		void render() override {
			Elements::Text::Text::render();
			if (ImGui::IsItemHovered()) {
				m_cont->setVisible();
			}
			m_cont->show();
			ImGui::SameLine();
			Elements::Text::Text::render();
		}

		void onHoveredIn() {
			m_cont->setVisible();
		}
	};







	class WindowTest : public IWindow
	{
	public:
		//bool m_selected
		
		WindowTest()
			: IWindow("ImGui window for test")
		{
			auto eventHandler = new Events::EventStd(EVENT_LAMBDA(info) {
				auto sender = info->getSender();
				auto text = static_cast<Elements::Input::FilterText*>(sender);
				auto val = text->getInputValue();
				val.pop_back();
			});

			getMainContainer()
				.addItem(new HoverText("text"))
				.beginChild()
					.setWidth(500)
					.setHeight(300)

					.beginTable()
						.setBorder(true)

						.beginHeader()
							.beginTD()
								.setWidth(200.f)
								.text("col 1").sameText("col 2")
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
									//.text("1 3")
									.addItem(
										(new Elements::Input::FilterText("enter here", 50, eventHandler))
										->setCompare(true)
										->addWord("cat")
										->addWord("dogs")
										->addWord("car")
									)
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