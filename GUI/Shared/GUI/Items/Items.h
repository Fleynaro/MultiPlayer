#pragma once

#include "main.h"
#include "../imgui_include.h"
#include "Attribute.h"
#include "Events.h"

#ifdef GUI_IS_MULTIPLAYER
#include "Utility/FileWrapper.h"
#include "Utility/Resource.h"
#endif


#define S_EVENT_LAMBDA(info) [](GUI::Events::EventInfo::Type & ##info) -> void
#define EVENT_LAMBDA(info) [this](GUI::Events::EventInfo::Type & ##info) -> void
#define EVENT_METHOD(name, info) inline void CALLBACK_##name(const GUI::Events::EventInfo::Type & ##info)
#define EVENT_METHOD_DEF(Class, name, info) inline void  ##Class::CALLBACK_##name(const GUI::Events::EventInfo::Type & ##info)
#define CALL_EVENT_METHOD(name, arg) CALLBACK_##name(GUI::Events::EventInfo::Type(new GUI::Events::EventInfo(##arg)));
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

	namespace Font
	{

	};

	class IInit
	{
	public:
		virtual void init() = 0;
	};

	class OnceInit : public IInit
	{
	public:
		OnceInit() = default;

		void call() {
			if (!m_inited) {
				init();
				m_inited = true;
			}
		}
	private:
		bool m_inited = false;
	};

#ifdef GUI_IS_MULTIPLAYER
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
#endif

	class Item
	{
	protected:
		virtual void render() = 0;
		virtual void onUpdate() {}
	public:
		virtual ~Item() {};

		void show() {
			onUpdate();

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

		void setDisplay(bool toggle) {
			m_display = toggle;
		}

		virtual bool isShown() {
			return m_display;
		}

		void setCanBeRemoved(bool state) {
			m_canBeRemoved = state;
		}
	protected:
		std::string getUniqueId() {
			return "##" + std::to_string((std::uintptr_t)this);
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

	class ImGuiContainer;
	class MenuContainer;
	class ColContainer;
	class TreeNode;
	class ChildContainer;
	class PopupContainer;
	class TabBar;
	class Container :
		public Item,
		public Events::ISender,
		public Events::OnVisible<Container>,
		public Attribute::Font<Container>
	{
	public:
		Container(std::string name = "")
			: Events::OnVisible<Container>(this)
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
		ChildContainer& beginChild();
		ChildContainer& beginChild(ChildContainer** ptr);
		PopupContainer& beginPopup(PopupContainer** ptr);
		TabBar& beginTabBar(std::string name);
		TabBar& beginTabBar(std::string name, TabBar** ptr);
		ColContainer& beginColContainer(std::string name);
		ColContainer& beginColContainer(std::string name, ColContainer** ptr);
		TreeNode& beginTreeNode(std::string name);
		TreeNode& beginTreeNode(std::string name, TreeNode** ptr);
		MenuContainer& beginMenu(std::string name);
		MenuContainer& beginMenu(std::string name, MenuContainer** ptr);
		ImGuiContainer& beginImGui(const std::function<void()> renderFunction);
		Container& end();
		Table::TR& endTD();

		Container& beginReverseInserting() {
			m_reverseInsert = true;
			return *this;
		}

		Container& endReverseInserting() {
			m_reverseInsert = false;
			return *this;
		}

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

		void onUpdate() override {
			sendVisibleEvent();
		}

		bool isVisible() override {
			return isShown();
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
		bool m_reverseInsert = false;
	};


	class TabItem :
		public Container,
		public Events::OnRightMouseClick<TabItem>,
		public Attribute::Id<TabItem>,
		public Attribute::Name<TabItem>
	{
	public:
		TabItem(std::string name)
			: Attribute::Name<TabItem>(name), Events::OnRightMouseClick<TabItem>(this)
		{}

		void render() override {
			pushIdParam();
			m_open = ImGui::BeginTabItem(getName().c_str());
			popIdParam();

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
		: public Container,
		public Attribute::Id<TabBar>,
		public Attribute::Name<TabBar>
	{
	public:
		TabBar(std::string name)
			: Attribute::Name<TabBar>(name)
		{}

		TabItem& beginTabItem(std::string name);
		TabItem& beginTabItem(std::string name, TabItem** ptr);

		void render() override {
			pushIdParam();
			bool isOpen = ImGui::BeginTabBar(getName().c_str());
			popIdParam();

			if (isOpen) {
				Container::render();
				ImGui::EndTabBar();
			}
		}
	};


	class TreeNode
		: public Container,
		public Attribute::Id<TreeNode>,
		public Attribute::Name<TreeNode>,
		public Attribute::Collapse<TreeNode>
	{
	public:
		TreeNode(const std::string& name = "##", bool open = false)
			: Attribute::Name<TreeNode>(name), Attribute::Collapse<TreeNode>(open)
		{}

		void render() override {
			if (isOpen()) {
				ImGui::SetNextItemOpen(true);
			}

			pushIdParam();
			bool isOpen = ImGui::TreeNode(getName().c_str());
			popIdParam();

			if (getName().find("##") != std::string::npos) {
				ImGui::SameLine();
				renderHeader();
				ImGui::NewLine();
			}
			if (isOpen) {
				Container::render();
				ImGui::TreePop();
			}
			else {
				close();
			}
		}

		virtual void renderHeader() {}
	};


	class ColContainer
		: public TreeNode
	{
	public:
		ColContainer(const std::string& name, bool open = true)
			: TreeNode(name, open)
		{}

		void render() override {
			pushIdParam();
			bool isOpen = ImGui::CollapsingHeader(getName().c_str(), m_closeBtn ? &m_open : nullptr);
			popIdParam();

			if (isOpen) {
				Container::render();
			}
		}

		ColContainer& setCloseBtn(bool toggle) {
			m_closeBtn = toggle;
			return *this;
		}
	private:
		bool m_closeBtn = false;
	};


	class ChildContainer :
		public Container,
		public Attribute::Id<ChildContainer>,
		public Attribute::ScrollbarX<Container>,
		public Attribute::ScrollbarY<Container>,
		public Attribute::Flags<Container, ImGuiWindowFlags_, ImGuiWindowFlags_::ImGuiWindowFlags_None>
	{
	public:
		ChildContainer() {}

		void render() override {
			pushIdParam();
			bool isOpen = ImGui::BeginChild("", ImVec2(m_width, m_height), m_border, getFlags());
			popIdParam();

			if (isOpen) {
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


	class PopupContainer
		: public Container,
		private Events::OnHovered<PopupContainer>
	{
	public:
		PopupContainer(bool display = false, int maxDeactiveTime = 1000)
			: m_maxDeactiveTime(maxDeactiveTime), Events::OnHovered<PopupContainer>(this)
		{}

		void setVisible() {
			m_lastActive = 0;
		}

		void setInvisible() {
			m_lastActive = GetTickCount64();
		}
	protected:
		bool isHovered() override {
			return ImGui::IsWindowHovered();
		}

		bool isShown() override {
			if (m_lastActive != 0 &&
				GetTickCount64() - m_lastActive >= m_maxDeactiveTime) {
				return false;
			}

			return true;
		}
		
		void render() override {
			bool isOpen = true;
			ImGui::SetNextWindowPos({ ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y });
			if (ImGui::Begin(getUniqueId().c_str(), &isOpen, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
			{
				if (!ImGui::IsWindowFocused()) {
					setInvisible();
				}
				else {
					sendHoveredEvent();
				}
				Container::render();
				ImGui::End();
			}
		}

		void onHoveredOut() override {
			setInvisible();
		}

		void onHoveredIn() override {
			setVisible();
		}
	private:
		int m_maxDeactiveTime;
		ULONGLONG m_lastActive = 1;
	};

	
	namespace Elements::Menu {
		class Item;
	};
	class MenuContainer : public TreeNode
	{
	public:
		MenuContainer(const std::string& name, bool open = true)
			: TreeNode(name, open)
		{}

		MenuContainer& menuItemWithShortcut(std::string name, std::string shortcut, Events::Event* event);
		MenuContainer& menuItem(std::string name, Events::Event* event);
		MenuContainer& menuItem(std::string name, Events::Event* event, Elements::Menu::Item** item);
		MenuContainer& menuItem(std::string name, Elements::Menu::Item** item);
		
		void render() override {
			if (ImGui::BeginMenu(getName().c_str(), isOpen())) {
				Container::render();
				ImGui::EndMenu();
			}
		}
	};


	class ImGuiContainer : public Container
	{
	public:
		ImGuiContainer(const std::function<void()>& renderFunction)
			: m_renderFunction(renderFunction)
		{}

		void render() override {
			m_renderFunction();
		}
	private:
		std::function<void()> m_renderFunction;
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

			TD& setWidth(float value) {
				m_width = value;
				return *this;
			}

			TD& setOffset(float value) {
				m_offset = value;
				return *this;
			}
		private:
			float m_width;
			float m_offset;
		};


		class Table;
		class Body;
		class TR
			: public Elem,
			public Attribute::Font<TR>
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
					ImGui::SetItemAllowOverlap();
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
			: public Elem,
			public Attribute::Font<Body>
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
				render(true);
			}

			void render(bool border) {
				pushFontParam();

				for (auto it : m_items) {
					if(border)
						ImGui::Separator();
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
			: public Elem,
			public Attribute::Font<Table>
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

			class Checkbox
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<Checkbox>,
				public Attribute::Id<Checkbox>,
				public Attribute::Name<Checkbox>
			{
			public:
				Checkbox(const std::string& name = "", bool state = false, Events::Event* event = nullptr)
					: Attribute::Name<Checkbox>(name), m_state(state), Events::OnSpecial<Checkbox>(this, event)
				{}

				void render() override
				{
					pushIdParam();
					bool isClicked = ImGui::Checkbox(getName().c_str(), &m_state);
					popIdParam();
					if (isClicked) {
						sendSpecialEvent();
					}
				}

				bool isSelected() {
					return m_state;
				}
			private:
				bool m_state;
			};
		};


		namespace Text
		{
			class Text
				: public Elem,
				public Attribute::Width<Text>,
				public Attribute::Font<Text>
			{
			public:
				Text(const std::string& text = "")
					: m_text(text)
				{}

				void render() override {
					pushWidthParam();
					pushFontParam();

					ImGui::Text(getText().c_str());

					popFontParam();
					popWidthParam();
				}

				Text* setText(const std::string& text) {
					m_text = text;
					return this;
				}

				const std::string& getText() {
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
			
#ifdef GUI_IS_MULTIPLAYER
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
#endif
		};


		namespace Button
		{
			class IButton
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<IButton>,
				public Attribute::Id<IButton>,
				public Attribute::Name<IButton>
			{
			public:
				IButton(std::string name, Events::Event* event)
					: Attribute::Name<IButton>(name), Events::OnSpecial<IButton>(this, event)
				{}
			};

			class ButtonStd
				: public IButton,
				public Attribute::Width<ButtonStd>,
				public Attribute::Height<ButtonStd>,
				public Attribute::Font<ButtonStd>
			{
			public:
				ButtonStd(std::string name, Events::Event* event = nullptr)
					: IButton(name, event)
				{}

				void render() override
				{
					pushFontParam();
					pushIdParam();

					if (ImGui::Button(getName().c_str(), ImVec2(getWidth(), getHeight()))) {
						sendSpecialEvent();
					}

					popIdParam();
					popFontParam();
				}
			};

			class ButtonSmall
				: public IButton,
				public Attribute::Font<ButtonSmall>
			{
			public:
				ButtonSmall(std::string name, Events::Event* event = nullptr)
					: IButton(name, event)
				{}

				void render() override
				{
					pushFontParam();
					pushIdParam();

					if (ImGui::SmallButton(getName().c_str())) {
						sendSpecialEvent();
					}

					popIdParam();
					popFontParam();
				}
			};
		};


		namespace Slider
		{
			template<typename T>
			class ISlider
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<ISlider<T>>,
				public Attribute::Id<ISlider<T>>,
				public Attribute::Name<ISlider<T>>
			{
			public:
				ISlider(std::string name, Events::Event* event, T min, T max, T value)
					: Attribute::Name<ISlider>(name), Events::OnSpecial<ISlider>(this, event), m_min(min), m_max(max), m_value(value)
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
					pushIdParam();
					if (ImGui::SliderFloat(getName().c_str(), &m_value, m_min, m_max)) {
						sendSpecialEvent();
					}
					popIdParam();
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
					pushIdParam();
					if (ImGui::SliderInt(getName().c_str(), &m_value, m_min, m_max)) {
						sendSpecialEvent();
					}
					popIdParam();
				}
			};
		};


		namespace Color
		{
			class IColorEdit
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<IColorEdit>,
				public Attribute::Name<IColorEdit>
			{
			public:
				IColorEdit(std::string name, Events::Event* event, ColorRGBA color)
					: Attribute::Name<IColorEdit>(name), Events::OnSpecial<IColorEdit>(this, event), m_color(color)
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
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<IInput>,
				public Attribute::Id<IInput>,
				public Attribute::Name<IInput>
			{
			public:
				IInput(const std::string& name, Events::Event* event)
					: Attribute::Name<IInput>(name), Events::OnSpecial<IInput>(this, event)
				{}
			};


			class Text
				: public IInput,
				public Attribute::Width<Text>,
				public Attribute::Font<Text>
			{
			public:
				Text(const std::string& name, int size, Events::Event* event)
					: m_size(size), IInput(name, event)
				{
					m_inputValue.reserve(size);
				}

				void render() override {
					pushWidthParam();
					pushFontParam();
					pushIdParam();

					if (ImGui::InputText(getName().c_str(), m_inputValue.data(), m_size)) {
						sendSpecialEvent();
					}

					popIdParam();
					popFontParam();
					popWidthParam();
				}

				Text* setInputValue(const std::string& inputText) {
					m_inputValue = inputText;
					return this;
				}

				std::string getInputValue() {
					return m_inputValue.c_str();
				}
			private:
				std::string m_inputValue;
				int m_size;
			};


			class FilterText
				: public Text,
				public Attribute::Collapse<FilterText>
			{
			public:
				FilterText(const std::string& name, int size, Events::Event* event)
					: Text(name, size, event), Attribute::Collapse<FilterText>(false)
				{}

				void render() override {
					Text::render();
					ImGui::SameLine();
					bool isFocused = ImGui::IsItemFocused();
					m_open |= ImGui::IsItemActive();
					if (isOpen())
					{
						ImGui::SetNextWindowPos({ ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y });
						ImGui::SetNextWindowSize({ ImGui::GetItemRectSize().x, 0 });
						if (ImGui::Begin(getUniqueId().c_str(), &m_open, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
						{
							isFocused |= ImGui::IsWindowFocused();
							for (auto& word : m_words) {
								if(m_isCompare && word.find(getInputValue()) == std::string::npos)
									continue;
								if (ImGui::Selectable(word.c_str()) || (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter)))
								{
									setInputValue(word);
									m_open = false;
								}
							}
							ImGui::End();
						}
						m_open &= isFocused;
					}
				}

				FilterText* setCompare(bool toggle) {
					m_isCompare = toggle;
					return this;
				}

				FilterText* addWord(const std::string& word) {
					m_words.push_back(word);
					return this;
				}

				void clear() {
					m_words.clear();
				}
			private:
				bool m_isCompare = false;
				std::vector<std::string> m_words;
			};


			class Float
				: public IInput,
				public Attribute::Width<Float>
			{
			public:
				Float(const std::string& name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();
					pushIdParam();

					if (ImGui::InputFloat(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popIdParam();
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
				: public IInput,
				public Attribute::Width<Float>
			{
			public:
				Double(const std::string& name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();
					pushIdParam();

					if (ImGui::InputDouble(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popIdParam();
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
				: public IInput,
				public Attribute::Width<Int>
			{
			public:
				Int(const std::string& name, Events::Event* event)
					: IInput(name, event)
				{}

				void render() override {
					pushWidthParam();
					pushIdParam();

					if (ImGui::InputInt(getName().c_str(), &m_value, m_step)) {
						sendSpecialEvent();
					}

					popIdParam();
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
				: public Elem,
				public Attribute::Width<Progress>
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
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<Item>
			{
			public:
				Item(Events::Event* event, int id)
					: Events::OnSpecial<Item>(this, event), m_id(id)
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
				: public List::Item,
				public Attribute::Name<RadioBtn>
			{
			public:
				RadioBtn(const std::string& name, int id, Events::Event* event = nullptr)
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
				: public List::Item,
				public Attribute::Name<MenuItem>
			{
			public:
				MenuItem(const std::string& name, int id, Events::Event* event = nullptr)
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
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<ListBox>,
				public Attribute::Id<ListBox>,
				public Attribute::Name<ListBox>,
				public Attribute::Width<ListBox>
			{
			public:
				ListBox(const std::string& name, int selected = 0, Events::Event * event = nullptr)
					: Attribute::Name<ListBox>(name), m_selected(selected), Events::OnSpecial<ListBox>(this, event)
				{}

				void render() override
				{
					if (m_items.empty())
						return;
					pushWidthParam();
					pushIdParam();
					bool isClicked = ImGui::ListBox(getName().c_str(), &m_selected, &m_items[0], (int)m_items.size(), m_height);
					popIdParam();

					if (isClicked) {
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
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<ListBoxDyn>,
				public Attribute::Id<ListBoxDyn>,
				public Attribute::Name<ListBoxDyn>,
				public Attribute::Width<ListBoxDyn>
			{
			public:
				using ItemListType = std::pair<std::vector<const char*>, std::vector<void*>>;
				using CallbackType = std::function<ItemListType()>;

				ListBoxDyn(const std::string& name, int selected = 0, Events::Event * event = nullptr)
					: Attribute::Name<ListBoxDyn>(name), m_selected(selected), Events::OnSpecial<ListBoxDyn>(this, event)
				{}

				void render() override
				{
					if (m_items.size() == 0)
						return;
					pushWidthParam();
					pushIdParam();
					bool isClicked = ImGui::ListBoxHeader(getName().c_str(), (int)m_items.size(), m_height);
					popIdParam();

					if (isClicked) {
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
				Combo(const std::string& name, int selected = 0, Events::Event * event = nullptr)
					: ListBox(name, selected, event)
				{}

				void render() override
				{
					pushWidthParam();
					pushIdParam();
					bool isClicked = ImGui::Combo(getName().c_str(), &m_selected, &m_items[0], (int)m_items.size(), m_height);
					popIdParam();

					if (isClicked) {
						sendSpecialEvent();
					}
					popWidthParam();
				}
			};

			class MultiCombo
				: public Elem,
				public Events::ISender,
				public Events::OnSpecial<MultiCombo>,
				public Attribute::Id<MultiCombo>,
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
				MultiCombo(const std::string& name, Events::Event* event = nullptr)
					: Attribute::Name<MultiCombo>(name), Events::OnSpecial<MultiCombo>(this, event)
				{}

				void render() override
				{
					pushWidthParam();
					pushIdParam();
					bool isClicked = ImGui::BeginCombo(getName().c_str(), getSelectedCategories().c_str());
					popIdParam();

					if (isClicked) {

						for (auto& item : m_items) {
							if (ImGui::Selectable(item.m_name.c_str(), &item.m_selected, getFlags())) {
								sendSpecialEvent();
							}
						}

						ImGui::EndCombo();
					}
					popWidthParam();
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
				public Events::ISender,
				public Events::OnSpecial<Item>,
				public Attribute::Name<Item>,
				public Attribute::Enable<Item>,
				public Attribute::Shortcut<Item>
			{
			public:
				Item(const std::string& name, Events::Event* event = nullptr, bool enable = true)
					: Events::OnSpecial<Item>(this, event), Attribute::Name<Item>(name), Attribute::Enable<Item>(enable)
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
				SelItem(const std::string& name, Events::Event* event = nullptr, bool select = false, bool enable = true)
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