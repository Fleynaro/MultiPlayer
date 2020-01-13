#pragma once

namespace GUI
{
	namespace Attribute
	{
		template<typename T>
		class Pos
		{
		public:
			Pos(float posX = -1.f, float posY = -1.f)
				: m_posX(posX), m_posY(posY)
			{};

			float getPosX() {
				return m_posX;
			}

			float getPosY() {
				return m_posY;
			}

			T* setPosX(float value) {
				m_posX = value;
				return (T*)this;
			}

			T* setPosY(float value) {
				m_posY = value;
				return (T*)this;
			}

			void pushPosParam() {
				if (getPosX() == -1.f)
					return;
				ImGui::SetNextWindowPos(ImVec2(m_posX, m_posY));
			}
		protected:
			float m_posX = -1.f;
			float m_posY = -1.f;
		};

		template<typename T>
		class Width
		{
		public:
			Width(float width = -1.f) : m_width(width) {};

			float getWidth() {
				return m_width;
			}

			T* setWidth(float value) {
				m_width = value;
				return (T*)this;
			}

			void pushWidthParam() {
				if (getWidth() == -1.f)
					return;
				ImGui::PushItemWidth(getWidth());
			}

			void popWidthParam() {
				if (getWidth() == -1.f)
					return;
				ImGui::PopItemWidth();
			}
		protected:
			float m_width;
		};

		template<typename T>
		class Font
		{
		public:
			Font(ImFont* font = nullptr) : m_font(font) {};

			ImFont* getFont() {
				return m_font;
			}

			T* setFont(ImFont* font) {
				m_font = font;
				return (T*)this;
			}

			void pushFontParam() {
				if (getFont() == nullptr)
					return;
				ImGui::PushFont(getFont());
			}

			void popFontParam() {
				if (getFont() == nullptr)
					return;
				ImGui::PopFont();
			}
		private:
			ImFont* m_font;
		};

		template<typename T>
		class Id
		{
		public:
			Id(std::string id)
				: m_id(id)
			{};

			std::string getId() {
				return m_id;
			}

			T* setId(std::string id) {
				m_id = id;
				return (T*)this;
			}
		private:
			std::string m_id;
		};

		template<typename T1, typename T2, T2 defFlag = 0>
		class Flags
		{
		public:
			Flags(T2 flags = defFlag)
				: m_flags(flags)
			{};

			T2 getFlags() {
				return m_flags;
			}

			T1* setFlags(T2 flags) {
				m_flags = flags;
				return (T1*)this;
			}
		private:
			T2 m_flags;
		};

		template<typename T>
		class Name
		{
		public:
			Name(std::string name) : m_name(name) {};

			virtual std::string getName() {
				return m_name;
			}

			T* setName(std::string value) {
				m_name = value;
				return (T*)this;
			}
		private:
			std::string m_name;
		};

		template<typename T>
		class Collapse
		{
		public:
			Collapse(bool open) : m_open(open) {};

			bool isOpen() {
				return m_open;
			}

			T& setOpen(bool state) {
				m_open = state;
				return *(T*)this;
			}

			T* open() {
				setOpen(true);
				return (T*)this;
			}

			T* close() {
				setOpen(false);
				return (T*)this;
			}
		protected:
			bool m_open = true;
		};

		template<typename T>
		class Enable
		{
		public:
			Enable(bool state) : m_enabled(state) {};

			bool isEnabled() {
				return m_enabled;
			}

			T& setEnable(bool state) {
				m_enabled = state;
				return *(T*)this;
			}

			T* enable() {
				setEnable(true);
				return (T*)this;
			}

			T* disable() {
				setEnable(false);
				return (T*)this;
			}
		protected:
			bool m_enabled = true;
		};

		template<typename T>
		class Select
		{
		public:
			Select(bool state) : m_selected(state) {};

			bool isSelected() {
				return m_selected;
			}

			T& setSelected(bool state) {
				m_selected = state;
				return *(T*)this;
			}

			T* select() {
				setSelected(true);
				return (T*)this;
			}

			T* unselect() {
				setSelected(false);
				return (T*)this;
			}
		protected:
			bool m_selected = true;
		};

		template<typename T>
		class ScrollbarY
		{
		public:
			ScrollbarY(float scrollBarY = -1.f)
				: m_scrollBarY(scrollBarY)
			{};

			float getScrollbarY() {
				return m_scrollBarY;
			}

			T* setScrollbarY(float value) {
				m_scrollBarY = value;
				return (T*)this;
			}

			T* setScrollbarToTop() {
				return setScrollbarY(0.f);
			}

			T* setScrollbarToBottom() {
				return setScrollbarY(-2.f);
			}

			void setScrollbarYParam() {
				if (m_scrollBarY == -1.f)
					return;
				if (m_scrollBarY == -2.f)
					ImGui::SetScrollY(ImGui::GetScrollMaxY());
				else ImGui::SetScrollY(m_scrollBarY);
			}
		protected:
			float m_scrollBarY;
		};

		template<typename T>
		class ScrollbarX
		{
		public:
			ScrollbarX(float scrollBarX = -1.f)
				: m_scrollBarX(scrollBarX)
			{};

			float getScrollbarX() {
				return m_scrollBarX;
			}

			T* setScrollbarY(float value) {
				m_scrollBarX = value;
				return (T*)this;
			}
		protected:
			float m_scrollBarX;
		};

		template<typename T, int Length = 40>
		class Rename
		{
		public:
			Rename(std::string newName = "")
				: m_newName(newName)
			{}

			void renderInput() {
				if (ImGui::InputText("##dirToRename", getInputName().data(), Length, ImGuiInputTextFlags_EnterReturnsTrue)) {
					enterInput();
				}
			}

			virtual void enterInput() = 0;

			std::string getInputName() {
				return m_newName.c_str();
			}

			void setInputName(std::string name) {
				getInputName() = name;
			}
		protected:
			std::string m_newName;
		};

		template<typename T>
		class Shortcut
		{
		public:
			Shortcut(std::string text = "")
				: m_shortcutText(text)
			{}
			
			const char* passShortcutText() {
				return getShortcutText().size() == 0 ? NULL : getShortcutText().c_str();
			}

			std::string& getShortcutText() {
				return m_shortcutText;
			}

			T* setShortcutText(std::string text) {
				m_shortcutText = text;
				return (T*)this;
			}
		protected:
			std::string m_shortcutText;
		};
	};
};