#pragma once
#include <fstream>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <queue>
#include <stack>
#include <atomic>
#include <thread>
#include <mutex>
#include <random>
#include <string>
#include <functional>
#include <windows.h>

#include "../imgui_include.h"

#include "Attribute.h"
#include "StyleThemes.h"


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

	static void DrawBorder(ColorRGBA color, float padding = 1.0) {
		auto min = ImGui::GetItemRectMin();
		auto max = ImGui::GetItemRectMax();
		min.x -= padding;
		min.y -= padding;
		max.x += padding;
		max.y += padding;
		ImGui::GetWindowDrawList()->AddRect(min, max, ImGui::GetColorU32(toImGuiColor(color)));
	}

	static void SameLine(float spacing = -1.f) {
		ImGui::SameLine(0.f, spacing);
	}

	static void Spacing() {
		ImGui::Spacing();
	}

	static void NewLine() {
		ImGui::NewLine();
	}

	static void Separator() {
		ImGui::Separator();
	}

	static bool CheckEventFlag(bool& value) {
		auto result = value;
		value = false;
		return result;
	}

	class GenericEvents
	{
		bool m_isClickedByLeftMouseBtn = false;
		bool m_isClickedByRightMouseBtn = false;
		bool m_isClickedByMiddleMouseBtn = false;

		bool m_isHovered = false;
		bool m_isHoveredIn = false;
		bool m_isHoveredOut = false;

		bool m_isFocused = false;
		bool m_isFocusedIn = false;
		bool m_isFocusedOut = false;

		bool m_isVisible = false;
		bool m_isVisibleOn = false;
		bool m_isVisibleOff = false;
	public:
		bool isClickedByLeftMouseBtn() {
			return CheckEventFlag(m_isClickedByLeftMouseBtn);
		}

		bool isClickedByRightMouseBtn() {
			return CheckEventFlag(m_isClickedByRightMouseBtn);
		}

		bool isClickedByMiddleMouseBtn() {
			return CheckEventFlag(m_isClickedByMiddleMouseBtn);
		}

		bool isHovered() {
			return ImGui::IsItemHovered();
		}

		bool isHoveredIn() {
			return CheckEventFlag(m_isHoveredIn);
		}

		bool isHoveredOut() {
			return CheckEventFlag(m_isHoveredOut);
		}

		bool isFocused() {
			return ImGui::IsItemFocused();
		}

		bool isFocusedIn() {
			return CheckEventFlag(m_isFocusedIn);
		}

		bool isFocusedOut() {
			return CheckEventFlag(m_isFocusedOut);
		}

		bool isVisible() {
			return ImGui::IsItemVisible();
		}

		bool isVisibleOn() {
			return CheckEventFlag(m_isVisibleOn);
		}

		bool isVisibleOff() {
			return CheckEventFlag(m_isVisibleOff);
		}

	protected:
		void processGenericEvents() {
			// mouse
			if(ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
				m_isClickedByLeftMouseBtn = true;

			if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1))
				m_isClickedByRightMouseBtn = true;

			if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(2))
				m_isClickedByMiddleMouseBtn = true;

			// hover
			if (isHovered()) {
				if (!m_isHovered) {
					m_isHovered = true;
					m_isHoveredIn = true;
					m_isHoveredOut = false;
				}
			}
			else {
				if (m_isHovered) {
					m_isHovered = false;
					m_isHoveredIn = false;
					m_isHoveredOut = true;
				}
			}

			// focus
			if (isFocused()) {
				if (!m_isFocused) {
					m_isFocused = true;
					m_isFocusedIn = true;
					m_isFocusedOut = false;
				}
			}
			else {
				if (m_isFocused) {
					m_isFocused = false;
					m_isFocusedIn = false;
					m_isFocusedOut = true;
				}
			}

			// visibility
			if (isVisible()) {
				if (!m_isVisible) {
					m_isVisible = true;
					m_isVisibleOn = true;
					m_isVisibleOff = false;
				}
			}
			else {
				if (m_isVisible) {
					m_isVisible = false;
					m_isVisibleOn = false;
					m_isVisibleOff = true;
				}
			}
		}
	};

	namespace Button
	{
		class AbstractButton
			: public Control,
			public GenericEvents,
			public Attribute::Id,
			public Attribute::Name
		{
		public:
			AbstractButton(const std::string& name)
				: Attribute::Name(name)
			{}

			bool present() {
				Control::show();
				return isClicked();
			}

			bool isClicked() {
				return CheckEventFlag(m_isClicked);
			}
		protected:
			bool m_isClicked = false;

			void renderControl() override {
				pushIdParam();
				renderButton();
				processGenericEvents();
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

		protected:
			void renderButton() override {
				pushFontParam();

				if (ImGui::Button(getName().c_str(), ImVec2(getWidth(), getHeight()))) {
					m_isClicked = true;
				}

				popFontParam();
			}
		};

		class ButtonArrow
			: public AbstractButton
		{
			ImGuiDir m_direction;
		public:
			ButtonArrow(ImGuiDir direction)
				: m_direction(direction), AbstractButton("##")
			{}

		protected:
			void renderButton() override
			{
				if (ImGui::ArrowButton(getName().c_str(), m_direction)) {
					m_isClicked = true;
				}
			}
		};

		class ButtonSmall
			: public AbstractButton,
			public Attribute::Font
		{
		public:
			ButtonSmall(const std::string& name)
				: AbstractButton(name)
			{}

		protected:
			void renderButton() override
			{
				pushFontParam();

				if (ImGui::SmallButton(getName().c_str())) {
					m_isClicked = true;
				}

				popFontParam();
			}
		};
	};

	namespace Input
	{
		class AbstractInput
			: public Control,
			public GenericEvents,
			public Attribute::Id,
			public Attribute::Name,
			public Attribute::Flags<
				ImGuiInputTextFlags,
				ImGuiInputTextFlags_None
			>
		{
			ColorRGBA m_borderColor = 0x0;
			ULONGLONG m_borderHideTime = 0;
		public:
			AbstractInput(const std::string& name)
				: Attribute::Name(name)
			{}

			void setReadOnly(bool toggle) {
				addFlags(ImGuiInputTextFlags_ReadOnly, toggle);
			}

			void showBorder(ColorRGBA color, int ms = 0) {
				m_borderColor = color;
				if (ms) {
					m_borderHideTime = GetTickCount64() + ms;
				}
				else {
					m_borderHideTime = 0;
				}
			}

			void hideBorder() {
				m_borderColor = 0x0;
			}

			/*void onExceptionOccured(const Exception& exception) override {
				showBorder(0xFF0000AA, 3000);
			}*/
		protected:
			void drawInputBorder() {
				if (m_borderColor != 0x0 && (m_borderHideTime == 0 || GetTickCount64() < m_borderHideTime)) {
					DrawBorder(m_borderColor);
				}
			}

			void renderControl() override {
				pushIdParam();
				renderInput();
				drawInputBorder();
				popIdParam();
			}

			virtual void renderInput() = 0;
		};

		class TextInput
			: public AbstractInput,
			public Attribute::Width,
			public Attribute::Font
		{
			std::string m_inputValue;
			bool m_isTextEntering = false;
		public:
			TextInput(const std::string& name = "")
				: AbstractInput(name)
			{}

			void setInputText(const std::string& inputText) {
				m_inputValue = inputText;
			}

			const std::string& getInputText() {
				return m_inputValue;
			}

			bool isTextEntering() {
				return CheckEventFlag(m_isTextEntering);
			}

		protected:
			void renderInput() override {
				pushWidthParam();
				pushFontParam();

				renderTextInput();

				popFontParam();
				popWidthParam();
			}

			virtual void renderTextInput() {
				if (ImGui::InputText(getName().c_str(), &m_inputValue, getFlags())) {
					m_isTextEntering = true;
				}
			}
		};

		class BoolInput
			: public AbstractInput
		{
			bool m_isClicked = false;
			bool m_value = false;
			bool m_tooltip = false;
		public:
			BoolInput(const std::string& name = "##", bool value = false)
				: AbstractInput(name), m_value(value)
			{}

			bool isClicked() {
				return CheckEventFlag(m_isClicked);
			}

			void setInputValue(bool value) {
				m_value = value;
			}

			bool getInputValue() {
				return m_value;
			}

			bool isSelected() {
				return m_value;
			}

			void setToolTip(bool toggle) {
				m_tooltip = toggle;
			}

		protected:
			void renderInput() override {
				m_isClicked = ImGui::Checkbox(m_tooltip ? "##tooltip" : getName().c_str(), &m_value);
				if (m_tooltip && ImGui::IsItemHovered())
					ImGui::SetTooltip(getName().c_str());
			}
		};

		class IntegerInput
			: public AbstractInput,
			public Attribute::Width
		{
			int m_value = 0;
			int m_step = 1;
			int m_fastStep = 100;
			bool m_isValueEntering = false;
		public:
			IntegerInput(const std::string& name = "##")
				: AbstractInput(name)
			{}

			void setInputValue(int value) {
				m_value = value;
			}

			int getInputValue() {
				return m_value;
			}

		protected:
			void renderControl() override {
				pushWidthParam();

				if (ImGui::InputInt(getName().c_str(), &m_value, m_step, m_fastStep, getFlags())) {
					m_isValueEntering = true;
				}

				popWidthParam();
			}
		};

		class FloatInput
			: public AbstractInput,
			public Attribute::Width
		{
			float m_value = 0;
			float m_step = 0.f;
			float m_fastStep = 0.0;
			bool m_isValueEntering = false;
		public:
			FloatInput(const std::string& name = "##")
				: AbstractInput(name)
			{}

			void setInputValue(float value) {
				m_value = value;
			}

			float getInputValue() {
				return m_value;
			}

		protected:
			void renderControl() override {
				pushWidthParam();

				if (ImGui::InputFloat(getName().c_str(), &m_value, m_step, m_fastStep, "%.3f", getFlags())) {
					m_isValueEntering = true;
				}

				popWidthParam();
			}
		};

		class DoubleInput
			: public AbstractInput,
			public Attribute::Width
		{
			double m_value = 0;
			double m_step = 0.0;
			double m_fastStep = 0.0;
			bool m_isValueEntering = false;
		public:
			DoubleInput(const std::string& name = "##")
				: AbstractInput(name)
			{}

			void setInputValue(double value) {
				m_value = value;
			}

			double getInputValue() {
				return m_value;
			}

		protected:
			void renderControl() override {
				pushWidthParam();

				if (ImGui::InputDouble(getName().c_str(), &m_value, m_step, m_fastStep, "%.6f", getFlags())) {
					m_isValueEntering = true;
				}

				popWidthParam();
			}
		};
	};

	namespace Text
	{
		class Text
			: public Control,
			public GenericEvents,
			public Attribute::Width,
			public Attribute::Font
		{
		public:
			Text(const std::string& text = "")
				: m_text(text)
			{}

			void setText(const std::string& text) {
				m_text = text;
			}

			const std::string& getText() {
				return m_text;
			}
		protected:
			std::string m_text;

			void renderControl() override {
				pushWidthParam();
				pushFontParam();

				renderText();
				processGenericEvents();

				popFontParam();
				popWidthParam();
			}

			virtual void renderText() {
				ImGui::Text(getText().c_str());
			}
		};

		class BulletText : public Text
		{
		public:
			BulletText(const std::string& text)
				: Text(text)
			{}

		protected:
			void renderText() override {
				ImGui::BulletText(m_text.c_str());
			}
		};

		class ColoredText : public Text
		{
			ColorRGBA m_color = 0x0;
		public:
			ColoredText(const std::string& text, ColorRGBA color)
				: Text(text), m_color(color)
			{}

			void setColor(ColorRGBA color) {
				m_color = color;
			}
		protected:
			void renderText() override {
				ImGui::TextColored(
					toImGuiColor(m_color),
					m_text.c_str()
				);
			}
		};
	};

	namespace Bar
	{
		class Progress
			: public Control,
			public Attribute::Width
		{
			float m_min;
			float m_max;
			float m_value;
			float m_width = 300.f;
			float m_height = 20.f;
		public:
			Progress(float value, float min = 0.f, float max = 100.f)
				: m_value(value), m_min(min), m_max(max)
			{}

			float getFraction() {
				return (m_value - m_min) / (m_max - m_min);
			}

			float getPercent() {
				return getFraction() * 100.f;
			}

			Progress* setValue(float value) {
				m_value = value;
				return this;
			}

			Progress* setMin(float value) {
				m_min = value;
				return this;
			}

			Progress* setMax(float value) {
				m_max = value;
				return this;
			}

			Progress* setWidth(float value) {
				m_width = value;
				return this;
			}

			Progress* setHeight(float value) {
				m_height = value;
				return this;
			}
		protected:
			void renderControl() override {
				pushWidthParam();

				ImGui::ProgressBar(getFraction(), ImVec2(m_width, m_height));

				popWidthParam();
			}
		};
	};

	class AbstractTreeView : public Control
	{
	public:
		AbstractTreeView()
		{}
	protected:
		class TreeNode :
			public Control
		{
			bool m_isOpened;
		public:
			TreeNode(const std::string& name) {
				m_isOpened = ImGui::TreeNode(name.c_str());
			}

			~TreeNode() {
				if(m_isOpened)
					ImGui::TreePop();
			}

			bool isOpened() {
				return m_isOpened;
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