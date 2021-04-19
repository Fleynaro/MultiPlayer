#pragma once
#include "main.h"
#include <Vendor/imgui-1.82/imgui_include.h>
#include "Attribute.h"


namespace GUI
{
	using Color = uint32_t;
	using ColorRGBA = Color;
	using ColorComponent = int;
	static inline ImVec4 toImGuiColor(ColorRGBA color) {
		ColorComponent A = color & 0xFF;
		ColorComponent R = color >> 24 & 0xFF;
		ColorComponent G = color >> 16 & 0xFF;
		ColorComponent B = color >> 8 & 0xFF;
		return ImColor(R, G, B, A);
	}

	class Control
	{
		bool m_display = true;
	protected:
		virtual ~Control() {};

		virtual void renderControl() = 0;

	public:
		void show() {
			if (isShown()) {
				renderControl();
			}
		}

		void setDisplay(bool toggle) {
			m_display = toggle;
		}

		virtual bool isShown() {
			return m_display;
		}
	};

	namespace Button
	{
		class AbstractButton
			: public Control,
			public Attribute::Id,
			public Attribute::Name
		{
		public:
			AbstractButton(const std::string& name)
				: Attribute::Name(name)
			{}

			bool isClicked() {
				auto isClicked = m_isClicked;
				m_isClicked = false;
				return isClicked;
			}
		protected:
			bool m_isClicked = false;

			void renderControl() override {
				pushIdParam();
				renderButton();
				popIdParam();
			}

			virtual void renderButton() = 0;
		};

		class StdButton
			: public AbstractButton,
			public Attribute::Width,
			public Attribute::Height,
			public Attribute::Font
		{
		public:
			StdButton(const std::string& name = "")
				: AbstractButton(name)
			{}

			void renderButton() override {
				pushFontParam();

				if (ImGui::Button(getName().c_str(), ImVec2(getWidth(), getHeight()))) {
					m_isClicked = true;
				}

				popFontParam();
			}
		};
	};

	class Window :
		public Control,
		public Attribute::Id,
		public Attribute::Name
	{
		bool m_open = true;
		bool m_focused = false;
		ImGuiWindowFlags m_flags = ImGuiWindowFlags_None;
	public:
		Window(const std::string& name)
			: Attribute::Name(name)
		{}

	protected:
		void renderControl() override {
			pushIdParam();
			bool isOpen = ImGui::Begin(getName().c_str(), &m_open, m_flags);
			popIdParam();

			if (isOpen)
			{
				renderWindow();
				ImGui::End();
			}

			checkIfClose();
		}

		virtual void renderWindow() = 0;

	private:
		void checkIfClose() {
			if (m_open == false) {

			}
		}
	};

	class WindowManager
	{
		std::list<Window*> m_windows;
	public:
		void addWindow(Window* window) {

			m_windows.push_back(window);
		}

		void removeWindow(Window* window) {
			m_windows.remove(window);
		}

		void renderAllWindows() {
			for (auto it : m_windows) {
				it->show();
			}
		}
	};

	class GUI
	{
	public:
		WindowManager* m_windowManager;

		GUI()
		{
			m_windowManager = new WindowManager;
		}

		void init(void* hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx)
		{
			IMGUI_CHECKVERSION();
			ImGui::CreateContext();
			ImGui_ImplWin32_Init(hwnd);
			ImGui_ImplDX11_Init(device, ctx);
			ImGui::StyleColorsDark();
		}

		void render()
		{
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();

			//ImGui::PushFont(GUI::Font::Tahoma);
			m_windowManager->renderAllWindows();
			//ImGui::PopFont();

			ImGui::Render();
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		}
	};
};