#pragma once

#include "main.h"
#include "../imgui_include.h"
#include "Attribute.h"
#include "Events.h"
#include "Utility/FileWrapper.h"
#include "Utility/Resource.h"


#define S_EVENT_LAMBDA(info) [](Events::EventInfo::Type & ##info) -> void
#define EVENT_LAMBDA(info) [this](Events::EventInfo::Type & ##info) -> void
#define EVENT_METHOD(name, info) inline void CALLBACK_##name(const Events::EventInfo::Type & ##info)
#define CALL_EVENT_METHOD(name, arg) CALLBACK_##name(Events::EventInfo::Type(new Events::EventInfo(##arg)));
#define EVENT_METHOD_PASS(name) EVENT_LAMBDA(info) {this->CALLBACK_##name(info);}

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

	class Font
	{
	public:
		inline static ImFont* Std = nullptr;
		inline static ImFont* Tahoma = nullptr;
		inline static ImFont* Tahoma_H3 = nullptr;
		inline static ImFont* Tahoma_H2 = nullptr;
		inline static ImFont* Tahoma_H1 = nullptr;
		inline static ImFont* Tahoma_small = nullptr;

		inline static ImFont* Consolas_12 = nullptr;
		inline static ImFont* Consolas_14 = nullptr;
		inline static ImFont* Consolas_16 = nullptr;

		static void init(HMODULE dll = nullptr)
		{
			ImGui::GetIO().Fonts->Clear();

			ImFontConfig font_config;
			font_config.OversampleH = 1; //or 2 is the same
			font_config.OversampleV = 1;
			font_config.PixelSnapH = 1;

			static const ImWchar ranges[] =
			{
				0x0020, 0x00FF, // Basic Latin + Latin Supplement
				0x0400, 0x044F, // Cyrillic
				0,
			};

			{
				auto file = FS::File(getWinFontDir(), "Tahoma.ttf");
				Tahoma_small = loadFontFromFile(file, 12.f, font_config, ranges);
				Std = Tahoma = loadFontFromFile(file, 14.f, font_config, ranges);
				Tahoma_H3 = loadFontFromFile(file, 16.f, font_config, ranges);
				Tahoma_H2 = loadFontFromFile(file, 19.f, font_config, ranges);
				Tahoma_H1 = loadFontFromFile(file, 22.f, font_config, ranges);
			}

			if (dll == nullptr)
				return;

			{
				FONT_Res res("FONT_CONSOLAS", dll);
				res.load();
				if (!res.isLoaded()) {
					//throw ex
					return;
				}
				
				Consolas_12 = loadFontFromRes(res, 12.f, font_config, ranges);
				Consolas_14 = loadFontFromRes(res, 14.f, font_config, ranges);
				Consolas_16 = loadFontFromRes(res, 16.f, font_config, ranges);
			}
		}

		static FS::Directory getWinFontDir() {
			return std::string("C:\\Windows\\Fonts");
		}

		static ImFont* loadFontFromFile(FS::File file, float size, const ImFontConfig& font_config, const ImWchar* ranges) {
			
			return ImGui::GetIO().Fonts->AddFontFromFileTTF(file.getFilename().c_str(), size, &font_config, ranges);
		}

		static ImFont* loadFontFromRes(FONT_Res& res, float size, const ImFontConfig& font_config, const ImWchar* ranges) {
			if (!res.isLoaded()) {
				res.load();
			}
			return ImGui::GetIO().Fonts->AddFontFromMemoryTTF(res.getData(), (int)res.getSize(), size, &font_config, ranges);
		}
	};


	class Item
	{
	public:
		virtual ~Item() {};
		virtual void render() = 0;

		void show() {
			if (isShown()) {
				render();
			}
		}

		void setParent(Item* parent) {
			if (getParent() != nullptr) {
				return;
			}
			setParentAnyway(parent);
		}

		void setParentAnyway(Item* parent) {
			m_parent = parent;
		}

		Item* getParent() {
			return m_parent;
		}

		bool canBeRemovedBy(Item* item) {
			return getParent() == item && m_canBeRemoved;
		}

		void setDisplay(bool state) {
			m_display = state;
		}

		bool isShown() {
			return m_display;
		}

		void setCanBeRemoved(bool state) {
			m_canBeRemoved = state;
		}
	private:
		Item* m_parent = nullptr;
		bool m_display = true;
		bool m_canBeRemoved = true;
	};

	
	class Elem : public Item
	{
	public:
	};

	
	namespace Elements::List {
		class Item;
	};
	class List : public Item
	{
	public:
		List(int value = 0, Events::Event *event = nullptr)
			: m_event(event), m_value(value)
		{}
		~List();
		List* addElem(Elements::List::Item* elem);

		void render() override;

		int getValue() {
			return m_value;
		}

		void setValue(int value) {
			m_value = value;
		}
	protected:
		std::vector<Elements::List::Item*> m_elems;
		Events::Event* m_event;
		int m_value ;
	};


	namespace Elements::List {
		class RadioBtn;
	};
	class ListRadioBtn : public List
	{
	public:
		ListRadioBtn(int value, Events::Event* event = nullptr)
			: List(value, event)
		{}
		
		ListRadioBtn* addRadioBtn(std::string name, int id);
	};


	namespace Elements::List {
		class MenuItem;
	};
	class ListMenuItem : public List
	{
	public:
		ListMenuItem(int value, Events::Event* event = nullptr)
			: List(value, event)
		{}
		
		ListMenuItem* addMenuItem(std::string name, int id);
	};


	namespace Elements::Text {
		class Text;
	};
	namespace Table {
		class Table;
		class TR;
	};

	class MenuContainer;
	class ColContainer;
	class TreeNode;
	class ChildContainer;
	class TabBar;
	class Container :
		public Item,
		public Attribute::Font<Container>
	{
	public:
		Container(std::string name = "")
		{}
		~Container() {
			clear();
		}
		Container& clear();

		Container& addItem(Item* item);
		Container& addItem(Item* item, Item** ptr);
		Container& addList(List* list);
		Container& addList(List* list, List** ptr);
		Container& sameLine(float spacing = -1.f);
		Container& newLine();
		Container& separator();
		Container& text(std::string value);
		Container& text(std::string value, uint32_t color);
		Container& text(std::string value, Elements::Text::Text** item);
		Container& ftext(const char* value, ...);
		Container& removeLastItem();

		Container& beginContainer();
		Container& beginContainer(Container** ptr);
		Table::Table& beginTable();
		Table::Table& beginTable(Table::Table** ptr);
		ChildContainer& beginChild(std::string name);
		ChildContainer& beginChild(std::string name, ChildContainer** ptr);
		TabBar& beginTabBar(std::string name);
		TabBar& beginTabBar(std::string name, TabBar** ptr);
		ColContainer& beginColContainer(std::string name);
		ColContainer& beginColContainer(std::string name, ColContainer** ptr);
		TreeNode& beginTreeNode(std::string name);
		TreeNode& beginTreeNode(std::string name, TreeNode** ptr);
		MenuContainer& beginMenu(std::string name);
		MenuContainer& beginMenu(std::string name, MenuContainer** ptr);
		Container& end();
		Table::TR& endTD();

		TabBar& backToTabBar() {
			return (TabBar&)end();
		}

		TreeNode& backToTreeNode() {
			return (TreeNode&)end();
		}

		ChildContainer& backToChild() {
			return (ChildContainer&)end();
		}

		MenuContainer& backToMenu() {
			return (MenuContainer&)end();
		}

		Container& setColor(ImGuiCol_ id, ColorRGBA color) {
			for (auto it : m_colors) {
				if (ImGuiCol_(it.first) == id) {
					it.second = color;
					return *this;
				}
			}

			m_colors.push_back(
				std::make_pair((std::byte)id, color)
			);
			return *this;
		}

		Container& setVar(ImGuiStyleVar id, const ImVec2& val) {
			return setVar(id, val.x, val.y);
		}

		Container& setVar(ImGuiStyleVar id, float value1, float value2 = -1) {
			for (auto it : m_vars) {
				if (ImGuiStyleVar(it.first) == id) {
					it.second.first = value1;
					it.second.second = value1;
					return *this;
				}
			}

			m_vars.push_back(
				std::make_pair((std::byte)id, std::make_pair(value1, value2))
			);
			return *this;
		}

		void pushSettings() {
			//push colors
			for (auto it : m_colors) {
				ImGui::PushStyleColor(
					(ImGuiCol_)it.first,
					toImGuiColor(it.second)
				);
			}
			
			//push vars with single arg
			for (auto it : m_vars) {
				if (it.second.second == -1) {
					ImGui::PushStyleVar(
						(ImGuiStyleVar)it.first,
						it.second.first
					);
				}
				else {
					ImGui::PushStyleVar(
						(ImGuiStyleVar)it.first,
						ImVec2(it.second.first, it.second.second)
					);
				}
			}

			pushFontParam();
		}

		void popSettings() {
			//pop colors
			for (auto it : m_colors) {
				ImGui::PopStyleColor();
			}

			//pop vars with single arg
			for (auto it : m_vars) {
				ImGui::PopStyleVar();
			}

			popFontParam();
		}

		void render() override {
			pushSettings();

			//render
			for (auto it : getItems()) {
				it->show();
			}

			popSettings();
		}

		std::list<Item*>& getItems() {
			return m_items;
		}
	protected:
		std::list<Item*> m_items;
		std::list<std::pair<std::byte, ColorRGBA>> m_colors;
		std::list<std::pair<std::byte, std::pair<float, float>>> m_vars;
	};


	class TabItem :
		public Container,
		public Attribute::Name<TabItem>,
		public Events::OnRightMouseClick<TabItem>
	{
	public:
		TabItem(std::string name)
			: Attribute::Name<TabItem>(name)
		{}

		void render() override {
			m_open = ImGui::BeginTabItem(getName().c_str());
			sendRightMouseClickEvent();
			if (isOpen()) {
				Container::render();
				ImGui::EndTabItem();
			}
		}

		bool isOpen() {
			return m_open;
		}
	protected:
		bool m_open = false;
	};


	class TabBar
		: public Container, public Attribute::Name<TabBar>
	{
	public:
		TabBar(std::string name)
			: Attribute::Name<TabBar>(name)
		{}

		TabItem& beginTabItem(std::string name);
		TabItem& beginTabItem(std::string name, TabItem** ptr);

		void render() override {
			if (ImGui::BeginTabBar(getName().c_str())) {
				Container::render();
				ImGui::EndTabBar();
			}
		}
	};


	class TreeNode
		: public Container, public Attribute::Name<TreeNode>, public Attribute::Collapse<TreeNode>
	{
	public:
		TreeNode(std::string name, bool open = false)
			: Attribute::Name<TreeNode>(name), Attribute::Collapse<TreeNode>(open)
		{}

		void render() override {
			if (isOpen()) {
				ImGui::SetNextTreeNodeOpen(true);
			}
			if (ImGui::TreeNode(getName().c_str())) {
				Container::render();
				ImGui::TreePop();
			}
		}
	};


	class ColContainer : public TreeNode
	{
	public:
		ColContainer(std::string name, bool open = true)
			: TreeNode(name, open)
		{}

		void render() override {
			if (ImGui::CollapsingHeader(getName().c_str(), &m_open)) {
				Container::render();
			}
		}
	};


	class ChildContainer :
		public Container,
		public Attribute::Id<ChildContainer>,
		public Attribute::ScrollbarX<Container>,
		public Attribute::ScrollbarY<Container>,
		public Attribute::Flags<Container, ImGuiWindowFlags_, ImGuiWindowFlags_::ImGuiWindowFlags_None>
	{
	public:
		ChildContainer(std::string id)
			: Attribute::Id<ChildContainer>(id)
		{}

		void render() override {
			if (ImGui::BeginChild(getId().c_str(), ImVec2(m_width, m_height), m_border, getFlags())) {
				setScrollbarYParam();
				Container::render();
				ImGui::EndChild();
			}
		}

		ChildContainer& setBorder(bool state) {
			m_border = state;
			return *this;
		}

		ChildContainer& setWidth(float value) {
			m_width = value;
			return *this;
		}

		ChildContainer& setHeight(float value) {
			m_height = value;
			return *this;
		}
	private:
		bool m_border = false;
		float m_width = 0.f;
		float m_height = 0.f;
	};

	
	namespace Elements::Menu {
		class Item;
	};
	class MenuContainer : public TreeNode
	{
	public:
		MenuContainer(std::string name, bool open = true)
			: TreeNode(name, open)
		{}

		MenuContainer& menuItemWithShortcut(const std::string& name, const std::string& shortcut, Events::Event* event);
		MenuContainer& menuItem(const std::string& name, Events::Event* event);
		MenuContainer& menuItem(const std::string& name, Events::Event* event, Elements::Menu::Item** item);
		MenuContainer& menuItem(const std::string& name, Elements::Menu::Item** item);
		
		void render() override {
			if (ImGui::BeginMenu(getName().c_str(), isOpen())) {
				Container::render();
				ImGui::EndMenu();
			}
		}
	};


	namespace Table
	{
		class TR;
		class TD : public Container
		{
		public:
			TD(float width = 0.f, float offset = 0.f)
				: m_width(width), m_offset(offset)
			{}

			void render() override {
				if (getWidth() > 0.f) {
					ImGui::SetColumnWidth(-1, getWidth());
				}
				if (getOffset() > 0.f) {
					ImGui::SetColumnOffset(-1, getOffset());
				}
				Container::render();
			}

			float getWidth() {
				return m_width;
			}

			float getOffset() {
				return m_offset;
			}

			void setWidth(float value) {
				m_width = value;
			}

			void setOffset(float value) {
				m_offset = value;
			}
		private:
			float m_width;
			float m_offset;
		};


		class Table;
		class Body;
		class TR
			: public Elem, public Attribute::Font<TR>
		{
		public:
			~TR() {
				for (auto it : m_columns) {
					if (it->canBeRemovedBy(this))
						delete it;
				}
			}

			TR& addTD(TD* td) {
				m_columns.push_back(td);
				td->setParent(this);
				return *this;
			}

			TD& beginTD(float width = 0.f, float offset = 0.f) {
				TD* ptr = nullptr;
				return beginTD(&ptr, width, offset);
			}

			TD& beginTD(TD** ptr, float width = 0.f, float offset = 0.f) {
				*ptr = new TD(width, offset);
				addTD(*ptr);
				return **ptr;
			}

			void render() override {
				pushFontParam();
				for (auto it : m_columns) {
					it->show();
					ImGui::NextColumn();
				}
				popFontParam();
			}

			int getColumnCount() {
				return (int)m_columns.size();
			}

			Body& endTR() {
				return *(Body*)getParent();
			}

			Table& endHeader() {
				return *(Table*)getParent();
			}
		private:
			std::list<TD*> m_columns;
		};

		
		class Body
			: public Elem, public Attribute::Font<Body>
		{
		public:
			~Body() {
				clear();
			}

			Body& clear() {
				for (auto it : m_items) {
					if (it->canBeRemovedBy(this))
						delete it;
				}
				m_items.clear();
				return *this;
			}

			Body& getBody(Body** body) {
				*body = this;
				return *this;
			}

			Body& addTR(TR* tr) {
				m_items.push_back(tr);
				tr->setParent(this);
				return *this;
			}

			TR& beginTR() {
				TR* ptr = nullptr;
				return beginTR(&ptr);
			}

			TR& beginTR(TR** ptr) {
				*ptr = new TR;
				addTR(*ptr);
				return **ptr;
			}

			void render() override {
				pushFontParam();

				for (auto it : m_items) {
					it->show();
				}

				popFontParam();
			}

			int getItemCount() {
				return (int)m_items.size();
			}

			Table& endBody() {
				return *(Table*)getParent();
			}
		private:
			std::list<TR*> m_items;
		};


		class Table
			: public Elem, public Attribute::Font<Table>
		{
		public:
			~Table() {
				delete m_header;
				if (m_body != nullptr) {
					delete m_body;
				}
			}

			TR& beginHeader() {
				m_header = new TR;
				m_header->setParent(this);
				return *m_header;
			}

			Body& beginBody() {
				Body* ptr = nullptr;
				return beginBody(&ptr);
			}

			Body& beginBody(Body** ptr) {
				*ptr = m_body = new Body;
				m_body->setParent(this);
				return *m_body;
			}

			TR& getHeader() {
				return *m_header;
			}

			Body& getBody() {
				return *m_body;
			}

			void render() override {
				pushFontParam();

				ImGui::Columns(getColumnCount(), nullptr, m_border);
				getHeader().show();
				if (m_body != nullptr) {
					getBody().show();
				}

				popFontParam();
			}

			int getColumnCount() {
				return getHeader().getColumnCount();
			}

			int getItemCount() {
				return getBody().getItemCount() / getColumnCount();
			}

			Table& setBorder(bool state) {
				m_border = state;
				return *this;
			}

			Container& end() {
				return *(Container*)getParent();
			}
		private:
			TR* m_header = nullptr;
			Body* m_body = nullptr;
			bool m_border = false;
		};
	};


	namespace Elements
	{
		namespace Generic
		{
			class SameLine : public Elem
			{
			public:
				SameLine(float spacing = -1.f)
					: m_spacing(spacing)
				{}

				void render() override {
					ImGui::SameLine(0.f, m_spacing);
				}
			private:
				float m_spacing;
			};

			class Spacing : public Elem
			{
			public:
				Spacing() {}

				void render() override {
					ImGui::Spacing();
				}
			};

			class NewLine : public Elem
			{
			public:
				NewLine() {}

				void render() override {
					ImGui::NewLine();
				}
			};

			class Separator : public Elem
			{
			public:
				Separator() {}

				void render() override {
					ImGui::Separator();
				}
			};
		};


		namespace Text
		{
			class Text
				: public Elem, public Attribute::Width<Text>, public Attribute::Font<Text>
			{
			public:
				Text(std::string text)
					: m_text(text)
				{}

				void render() override {
					pushWidthParam();
					pushFontParam();

					ImGui::Text(getText().c_str());

					popFontParam();
					popWidthParam();
				}

				Text* setText(std::string text) {
					m_text = text;
					return this;
				}

				std::string& getText() {
					return m_text;
				}
			protected:
				std::string m_text;
			};

			class BulletText : public Text
			{
			public:
				BulletText(std::string text) : Text(text) {}
				
				void render() override {
					pushWidthParam();
					pushFontParam();

					ImGui::BulletText(m_text.c_str());

					popFontParam();
					popWidthParam();
				}
			};

			class ColoredText : public Text
			{
			public:
				ColoredText(std::string text, ColorRGBA color)
					: Text(text), m_color(color)
				{}

				void render() override {
					pushFontParam();

					ImGui::TextColored(
						toImGuiColor(m_color),
						m_text.c_str()
					);

					popFontParam();
				}

				void setColor(ColorRGBA color) {
					m_color = color;
				}
			protected:
				ColorRGBA m_color = 0x0;
			};
			
			class FormatedText : public Elem
			{
				inline static const char ColorMarkerStart = '{';
				inline static const char ColorMarkerEnd = '}';
			public:
				FormatedText() {}
				~FormatedText() {
					for (auto it : m_elems) {
						if (it->canBeRemovedBy(this))
							delete it;
					}
				}

				FormatedText* addItem(Elem* elem) {
					m_elems.push_back(elem);
					elem->setParent(this);
					return this;
				}

				FormatedText* clear() {
					m_elems.clear();
					return this;
				}

				FormatedText* parse(const char* fmt, ...)
				{
					char tempStr[4096];

					va_list argPtr;
					va_start(argPtr, fmt);
					_vsnprintf_s(tempStr, sizeof(tempStr), fmt, argPtr);
					va_end(argPtr);
					tempStr[sizeof(tempStr) - 1] = '\0';


					ColorRGBA nextColor = m_colorStd;
					ImFont* nextFont = Font::Std;
					const char* textStart = tempStr;
					const char* textCur = tempStr;
					while (textCur < (tempStr + sizeof(tempStr)) && *textCur != '\0')
					{
						if (*textCur == ColorMarkerStart)
						{
							// Print accumulated text
							if (textCur != textStart)
							{
								addColoredText(textStart, textCur, nextColor, nextFont);
								addItem(new Elements::Generic::SameLine(0.f));
							}

							// Process color code
							const char* colorStart = textCur + 1;
							do
							{
								++textCur;
							} while (*textCur != '\0' && *textCur != ColorMarkerEnd);


							if (int(colorStart - textCur) == 0)
							{
								nextColor = m_colorStd;
								nextFont = Font::Std;
							}
							else {
								ColorRGBA textColor;
								if (ProcessInlineHexColor(colorStart, textCur, textColor)) {
									nextColor = textColor;
								}
								else {
									ImFont* textFont;
									if (ProcessInlineHexFont(colorStart, textCur, &textFont)) {
										nextFont = textFont;
									}
								}
							}

							textStart = textCur + 1;
						}
						else if (*textCur == '\n')
						{
							// Print accumulated text an go to next line
							addColoredText(textStart, textCur, nextColor, nextFont);
							textStart = textCur + 1;
						}

						++textCur;
					}

					if (textCur != textStart)
					{
						addColoredText(textStart, textCur, nextColor, nextFont);
					}
					else
					{
						addItem(new Elements::Generic::NewLine);
					}
					return this;
				}
			private:
				void addColoredText(const char* text, const char* end, ColorRGBA color, ImFont* font) {
					addItem(
						(new Elements::Text::ColoredText(
							std::string(text).substr(0, end - text), color
						))->setFont(font)
					);
				}

			public:
				void render() override {
					for (auto it : m_elems) {
						it->show();
					}
				}
			private:
				bool ProcessInlineHexColor(const char* start, const char* end, ColorRGBA& color)
				{
					const int hexCount = (int)(end - start);
					if (hexCount == 6 || hexCount == 8)
					{
						char hex[9];
						strncpy_s(hex, start, hexCount);
						hex[hexCount] = 0;
						
						if (sscanf_s(hex, "%x", &color) > 0)
						{
							if (hexCount == 6) {
								color <<= 8;
								color |= 0xFF;
							}
							return true;
						}
					}

					return false;
				}

				bool ProcessInlineHexFont(const char* start, const char* end, ImFont** font)
				{
					const int hexCount = (int)(end - start);
					if (hexCount == 2)
					{
						if (start[1] >= '1' && start[1] <= '3')
						{
							if (start[1] == '3')
								*font = Font::Tahoma_H3;
							else if (start[1] == '2')
								*font = Font::Tahoma_H2;
							else if (start[1] == '1')
								*font = Font::Tahoma_H1;
							return true;
						}
					}

					return false;
				}
			protected:
				std::list<Elem*> m_elems;
				ColorRGBA m_colorStd = 0xFFFFFFFF;
			};
		};


		namespace Button
		{
			class IButton
				: public Elem, public Events::OnSpecial, public Attribute::Name<IButton>
			{
			public:
				IButton(std::string name, Events::Event* event)
					: Attribute::Name<IButton>(name), Events::OnSpecial(event)
				{}
			};

			class ButtonStd
				: public IButton, public Attribute::Width<ButtonStd>, public Attribute::Font<ButtonStd>
			{
			public:
				ButtonStd(std::string name, Events::Event* event = nullptr)
					: IButton(name, event)
				{}

				void render() override
				{
					pushWidthParam();
					pushFontParam();

					if (ImGui::Button(getName().c_str())) {
						sendSpecialEvent();
					}

					popFontParam();
					popWidthParam();
				}
			};

			class ButtonSmall
				: public IButton, public Attribute::Width<ButtonSmall>, public Attribute::Font<ButtonSmall>
			{
			public:
				ButtonSmall(std::string name, Events::Event* event = nullptr)
					: IButton(name, event)
				{}

				void render() override
				{
					pushWidthParam();
					pushFontParam();

					if (ImGui::SmallButton(getName().c_str())) {
						sendSpecialEvent();
					}

					popFontParam();
					popWidthParam();
				}
			};
		};


		namespace Slider
		{
			template<typename T>
			class ISlider
				: public Elem, public Events::OnSpecial, public Attribute::Name<ISlider<T>>
			{
			public:
				ISlider(std::string name, Events::Event* event, T min, T max, T value)
					: Attribute::Name<ISlider>(name), Events::OnSpecial(event), m_min(min), m_max(max), m_value(value)
				{}

				void setMin(T value) {
					m_min = value;
				}

				T getMin() {
					return m_min;
				}

				void setMax(T value) {
					m_max = value;
				}

				T getMax() {
					return m_max;
				}

				void setValue(T value) {
					m_value = value;
				}

				T getValue() {
					return m_value;
				}
			protected:
				std::string m_name;
				T m_min;
				T m_max;
				T m_value;
			};

			//standart slider float
			class SliderFloat : public ISlider<float>
			{
			public:
				SliderFloat(std::string name, Events::Event* event = nullptr, float min = 0.0, float max = 1.0, float value = 0.0)
					: ISlider(name, event, min, max, value)
				{}

				void render() override
				{
					if (ImGui::SliderFloat(getName().c_str(), &m_value, m_min, m_max)) {
						sendSpecialEvent();
					}
				}
			};

			//standart slider int
			class SliderInt : public ISlider<int>
			{
			public:
				SliderInt(std::string name, Events::Event* event = nullptr, int min = 0, int max = 100, int value = 0.0)
					: ISlider(name, event, min, max, value)
				{}

				void render() override
				{
					if (ImGui::SliderInt(getName().c_str(), &m_value, m_min, m_max)) {
						sendSpecialEvent();
					}
				}
			};
		};


		namespace Color
		{
			class IColorEdit
				: public Elem, public Events::OnSpecial, public Attribute::Name<IColorEdit>
			{
			public:
				IColorEdit(std::string name, Events::Event* event, ColorRGBA color)
					: Attribute::Name<IColorEdit>(name), Events::OnSpecial(event), m_color(color)
				{}

				ColorRGBA getColor() {
					return m_color;
				}
			protected:
				ColorRGBA m_color;
			};


			class ColorEditStd : public IColorEdit
			{
			public:
				ColorEditStd(std::string name, Events::Event* event, ColorRGBA color = ColorRGBA(0xFF0000FF))
					: IColorEdit(name, event, color)
				{}

				void render() override
				{
					ImVec4 color = ImGui::ColorConvertU32ToFloat4(m_color);
					if (ImGui::ColorEdit3(getName().c_str(), (float*)& color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel)) {
						m_color = ImGui::ColorConvertFloat4ToU32(color);
						sendSpecialEvent();
					}
				}
			};
		};



		namespace Input
		{
			class IInput
				: public Elem, public Events::OnSpecial, public Attribute::Name<IInput>
			{
			public:
				IInput(std::string name, Events::Event* event)
					: Attribute::Name<IInput>(name), Events::OnSpecial(event)
				{}
			};


			class Text
				: public IInput, public Attribute::Width<Text>, public Attribute::Font<Text>
			{
			public:
				Text(std::string name, int size, Events::Event* event)
					: m_size(size), IInput(name, event)
				{
					m_inputValue.reserve(size);
				}

				void render() override {
					pushWidthParam();
					pushFontParam();

					if (ImGui::InputText(getName().c_str(), m_inputValue.data(), m_size)) {
						sendSpecialEvent();
					}

					popFontParam();
					popWidthParam();
				}

				std::string getInputValue() {
					return m_inputValue.c_str();
				}
			private:
				std::string m_inputValue;
				int m_size;
			};


			class Float
				: public IInput, public Attribute::Width<Float>
			{
			public:
				Float(std::string name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();

					if (ImGui::InputFloat(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popWidthParam();
				}

				Float* setInputValue(float value) {
					m_value = value;
					return this;
				}

				float getInputValue() {
					return m_value;
				}
			private:
				float m_value = 0;
				float m_step = 0.f;
			};


			class Double
				: public IInput, public Attribute::Width<Float>
			{
			public:
				Double(std::string name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();

					if (ImGui::InputDouble(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popWidthParam();
				}

				Double* setInputValue(double value) {
					m_value = value;
					return this;
				}

				double getInputValue() {
					return m_value;
				}
			private:
				double m_value = 0;
				double m_step = 0.0;
			};


			class Int
				: public IInput, public Attribute::Width<Int>
			{
			public:
				Int(std::string name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();

					if (ImGui::InputInt(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popWidthParam();
				}

				Int* setInputValue(int value) {
					m_value = value;
					return this;
				}

				int getInputValue() {
					return m_value;
				}
			private:
				int m_value = 0;
				int m_step = 0;
			};
		};



		namespace Bar
		{
			class Progress
				: public Elem, public Attribute::Width<Progress>
			{
			public:
				Progress(float value, float min = 0.f, float max = 100.f)
					: m_value(value), m_min(min), m_max(max)
				{}

				void render() override {
					pushWidthParam();

					ImGui::ProgressBar(getFraction(), ImVec2(m_width, m_height));

					popWidthParam();
				}

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
				float m_min;
				float m_max;
				float m_value;
				float m_width = 300.f;
				float m_height = 20.f;
			};
		};


		namespace List
		{
			class Item
				: public Elem, public Events::OnSpecial
			{
			public:
				Item(Events::Event* event, int id)
					: Events::OnSpecial(event), m_id(id)
				{}

				void setValuePtr(int* ptr) {
					m_value = ptr;
				}

				int* getValuePtr() {
					return m_value;
				}

				int getValue() {
					return *m_value;
				}

				bool isSelected() {
					return m_id == getValue();
				}

				void makeSelected() {
					*m_value = m_id;
				}
			protected:
				int m_id;
				int* m_value = nullptr;
			};


			class RadioBtn
				: public List::Item, public Attribute::Name<RadioBtn>
			{
			public:
				RadioBtn(std::string name, int id, Events::Event* event = nullptr)
					: Attribute::Name<RadioBtn>(name), List::Item(event, id)
				{}

				void render() override
				{
					if (ImGui::RadioButton(getName().c_str(), getValuePtr(), m_id)) {
						sendSpecialEvent();
					}
				}
			};


			class MenuItem
				: public List::Item, public Attribute::Name<MenuItem>
			{
			public:
				MenuItem(std::string name, int id, Events::Event* event = nullptr)
					: Attribute::Name<MenuItem>(name), List::Item(event, id)
				{}

				void render() override
				{
					if (ImGui::MenuItem(getName().c_str(), NULL, List::Item::isSelected())) {
						makeSelected();
						sendSpecialEvent();
					}
				}
			};


			class ListBox
				: public Elem, public Events::OnSpecial, public Attribute::Name<ListBox>, public Attribute::Width<ListBox>
			{
			public:
				ListBox(std::string name, int selected = 0, Events::Event * event = nullptr)
					: Attribute::Name<ListBox>(name), m_selected(selected), Events::OnSpecial(event)
				{}

				void render() override
				{
					if (m_items.empty())
						return;
					pushWidthParam();

					if (ImGui::ListBox(getName().c_str(), &m_selected, &m_items[0], (int)m_items.size(), m_height)) {
						sendSpecialEvent();
					}

					popWidthParam();
				}

				ListBox* clear() {
					m_items.clear();
					return this;
				}

				ListBox* addItem(const char* itemName) {
					m_items.push_back(itemName);
					return this;
				}

				ListBox* setHeight(int value) {
					m_height = value;
					return this;
				}

				ListBox* setDefault(int value) {
					m_selected = value;
					return this;
				}

				int getSelectedItem() {
					return m_selected;
				}
			protected:
				std::vector<const char*> m_items;
				int m_selected;
				int m_height = -1;
			};


			class ListBoxDyn
				: public Elem, public Events::OnSpecial, public Attribute::Name<ListBoxDyn>, public Attribute::Width<ListBoxDyn>
			{
			public:
				using ItemListType = std::pair<std::vector<const char*>, std::vector<void*>>;
				using CallbackType = std::function<ItemListType()>;

				ListBoxDyn(std::string name, int selected = 0, Events::Event * event = nullptr)
					: Attribute::Name<ListBoxDyn>(name), m_selected(selected), Events::OnSpecial(event)
				{}

				void render() override
				{
					if (m_items.size() == 0)
						return;
					pushWidthParam();

					if (ImGui::ListBoxHeader(getName().c_str(), (int)m_items.size(), m_height)) {
						int i = 0;
						for (auto it : m_items) {
							if (ImGui::Selectable(it.first.c_str(), i == m_selected)) {
								m_selected = i;
								m_itemSelected = it.second;
								sendSpecialEvent();
							}
							i++;
						}

						ImGui::ListBoxFooter();
					}
					selectByPtr(m_itemSelected);

					popWidthParam();
				}
				
				void selectByPtr(void* ptr) {
					m_selected = 0;
					for (auto it : m_items) {
						if (it.second == ptr) {
							m_itemSelected = ptr;
							return;
						}
						m_selected++;
					}
					//if not found
					m_selected = 0;
					m_itemSelected = m_items.begin()->second;
				}
			public:
				ListBoxDyn* clear() {
					m_items.clear();
					return this;
				}

				ListBoxDyn* setHeight(int value) {
					m_height = value;
					return this;
				}

				ListBoxDyn* setDefault(int value) {
					m_selected = value;
					return this;
				}

				ListBoxDyn* addItem(std::string label, void* ptr) {
					m_items.push_back(
						std::make_pair(label, ptr)
					);
					return this;
				}

				int getSelectedItem() {
					return m_selected;
				}

				void* getSelectedItemPtr() {
					return m_itemSelected;
				}
			protected:
				std::list<std::pair<std::string, void*>> m_items;
				void* m_itemSelected = nullptr;
				int m_selected;
				int m_height = -1;
			};


			class Combo : public ListBox
			{
			public:
				Combo(std::string name, int selected = 0, Events::Event * event = nullptr)
					: ListBox(name, selected, event)
				{}

				void render() override
				{
					if (ImGui::Combo(getName().c_str(), &m_selected, &m_items[0], (int)m_items.size(), m_height)) {
						sendSpecialEvent();
					}
				}
			};


			class MultiCombo
				: public Elem,
				public Events::OnSpecial,
				public Attribute::Name<MultiCombo>,
				public Attribute::Width<MultiCombo>,
				public Attribute::Flags<
					MultiCombo,
					ImGuiSelectableFlags_,
					ImGuiSelectableFlags_::ImGuiSelectableFlags_DontClosePopups
				>
			{
				struct ComboItem {
					std::string m_name = "";
					bool m_selected = false;
					void* m_userPtr = nullptr;
				};
			public:
				MultiCombo(std::string name, Events::Event* event = nullptr)
					: Attribute::Name<MultiCombo>(name), Events::OnSpecial(event)
				{}

				void render() override
				{
					if (ImGui::BeginCombo(getName().c_str(), getSelectedCategories().c_str())) {

						for (auto& item : m_items) {
							if (ImGui::Selectable(item.m_name.c_str(), &item.m_selected, getFlags())) {
								sendSpecialEvent();
							}
						}

						ImGui::EndCombo();
					}
				}

				void addSelectable(const std::string& name, bool selected = false, void* userPtr = nullptr) {
					ComboItem item;
					item.m_name = name;
					item.m_selected = selected;
					item.m_userPtr = userPtr;
					m_items.push_back(item);
				}

				std::vector<ComboItem>& getSelectedItems() {
					return m_items;
				}

				ComboItem& getItem(int itemIdx) {
					return m_items[itemIdx];
				}

				bool isSelected(int itemIdx) {
					return getItem(itemIdx).m_selected;
				}
			private:
				std::vector<ComboItem> m_items;

				std::string getSelectedCategories() {
					std::string categories = "";
					for (auto& item : m_items) {
						if (item.m_selected)
							categories += item.m_name + ",";
					}
					if (m_items.size() > 0)
						categories.pop_back();
					return categories;
				}
			};
		};



		namespace Menu
		{
			class Item :
				public Elem,
				public Events::OnSpecial,
				public Attribute::Name<Item>,
				public Attribute::Enable<Item>,
				public Attribute::Shortcut<Item>
			{
			public:
				Item(std::string name, Events::Event* event = nullptr, bool enable = true)
					: Events::OnSpecial(event), Attribute::Name<Item>(name), Attribute::Enable<Item>(enable)
				{}

				void render() override
				{
					if (ImGui::MenuItem(getName().c_str(), passShortcutText(), false, isEnabled())) {
						sendSpecialEvent();
					}
				}
			};

			class SelItem :
				public Item,
				public Attribute::Select<SelItem>
			{
			public:
				SelItem(std::string name, Events::Event* event = nullptr, bool select = false, bool enable = true)
					: Item(name, event, enable), Attribute::Select<SelItem>(select)
				{}

				void render() override
				{
					if (ImGui::MenuItem(getName().c_str(), passShortcutText(), &m_selected, isEnabled())) {
						sendSpecialEvent();
					}
				}
			};
		};
	};
};