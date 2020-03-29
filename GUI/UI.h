#pragma once

#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"
#include "TestWindows.h"
#include "GUI/Widgets/PageNavigation.h"

using namespace GUI::Window;
using namespace GUI::Widget;


namespace Utils
{
	template<int PrimaryKeyColumnIdx, typename ...ColumnsType>
	class Table
	{
	public:
		using Tuple = std::tuple<ColumnsType...>;
		using PrimaryKeyColumnType = typename std::tuple_element<PrimaryKeyColumnIdx, Tuple>::type;

		Table() = default;

		void addRow(ColumnsType... values) {
			auto tuple = Tuple(values...);
			m_rows.insert(std::make_pair(std::get<PrimaryKeyColumnIdx>(tuple), tuple));
		}

		bool hasRow(PrimaryKeyColumnType key) {
			return m_rows.find(key) != m_rows.end();
		}

		Tuple* getRow(PrimaryKeyColumnType key) {
			return hasRow(key) ? &m_rows[key] : nullptr;
		}

		void removeRow(PrimaryKeyColumnType key) {
			m_rows.erase(key);
		}

		Tuple* operator [] (PrimaryKeyColumnType key) {
			return getRow(key);
		}

		class Result
		{
		public:
			Result(Table* table)
				: m_table(table)
			{}

			template<int SortColumnIdx>
			Result& orderBy(bool descending = false) {
				return descending ? orderBy<SortColumnIdx, true>() : orderBy<SortColumnIdx, false>();
			}

			template<int SortColumnIdx, bool Descending = false>
			Result& orderBy() {
				return orderBy([](const Tuple& a, const Tuple& b) {
					if constexpr(Descending)
						return std::get<SortColumnIdx>(a) > std::get<SortColumnIdx>(b);
					else return std::get<SortColumnIdx>(a) < std::get<SortColumnIdx>(b);
				});
			}

			Result& orderBy(const std::function<bool(const Tuple&, const Tuple&)>& functor) {
				m_rowsIndexes.sort([&](const PrimaryKeyColumnType& idx1, const PrimaryKeyColumnType& idx2) {
					return functor(*m_table->getRow(idx1), *m_table->getRow(idx2));
				});
				return *this;
			}

			std::list<PrimaryKeyColumnType>& getList() {
				return m_rowsIndexes;
			}
		private:
			Table* m_table;
			std::list<PrimaryKeyColumnType> m_rowsIndexes;
		};

		Result where(const std::function<bool(const Tuple&)>& filter) {
			Result result(this);
			for (auto it : m_rows) {
				if (filter(it.second)) {
					result.getList().push_back(it.first);
				}
			}
			return result;
		}

		Result all() {
			return where([](const Tuple& tuple) { return true; });
		}
	private:
		std::map<PrimaryKeyColumnType, Tuple> m_rows;
	};
};


class TriggerTable : public Utils::Table<0, int, int, std::string>
{
public:
	enum class Columns {
		CallId,
		TriggerId,
		FunctionId
	};

	TriggerTable()
	{}
};

namespace GUI::Widget
{
	class TableView : public Container
	{
	public:
		class Column
			: public Elem,
			public Events::OnLeftMouseClick<Column>
		{
		public:
			std::string m_name;
			enum class Order {
				Default,
				Asc,
				Desc,
				Disabled
			};
			Order m_order;
			int m_idx;

			Column(int idx, const std::string& name, bool order = false)
				: m_idx(idx), m_name(name), m_order(order ? Order::Default : Order::Disabled),
				Events::OnLeftMouseClick<Column>(this, this)
			{}

			void setOrder(Order order) {
				m_order = order;
			}

			void nextOrder() {
				if (m_order == Order::Default)
					m_order = Order::Asc;
				else if (m_order == Order::Asc)
					m_order = Order::Desc;
				else if (m_order == Order::Desc)
					m_order = Order::Default;
			}

			bool isDescending() {
				return m_order == Order::Desc;
			}

			void render() override {
				ImGui::Text(m_name.c_str());

				if (m_order != Order::Disabled)
				{
					if (ImGui::IsItemHovered()) {
						ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
					}

					sendLeftMouseClickEvent();
					ImGui::SameLine();

					switch (m_order)
					{
					case Order::Asc:
						ImGui::Text(" (Asc)");
						break;
					case Order::Desc:
						ImGui::Text(" (Desc)");
						break;
					default:
						ImGui::NewLine();
					}
				}
			}
		};

		TableView()
		{
			m_table = new Table::Table;
			m_table->beginHeader();
			m_table->beginBody();

			addItem(m_textBox = new Elements::Input::Text);
			m_textBox->getSpecialEvent() += [=](Events::ISender* sender) {
				onSearch(m_textBox->getInputValue());
			};
			sameLine();

			auto combo = new Elements::List::Combo("");
			addItem(combo);
			combo->addItem("20 rows");
			combo->addItem("50 rows");
			combo->addItem("100 rows");
			combo->addItem("300 rows");
			combo->getSpecialEvent() += [=](Events::ISender* sender) {
				int arr[] = { 20, 50, 100, 300 };
				setRowsCountOnPage(arr[combo->getSelectedItem()]);
				update();
			};

			addItem(m_table);
			addItem(m_pageNav = new Widget::PageNavigation);
			setRowsCountOnPage(20);
			m_pageNav->getSelectPageEvent() += [&](int oldPage, int newPage) {
				update();
			};
		}

		~TableView() {
			for (auto column : m_columns) {
				column->destroy();
			}
		}

		virtual void update() = 0;
	private:
		Table::Table* m_table;
		Widget::PageNavigation* m_pageNav;
		Elements::Input::Text* m_textBox;
	protected:
		std::list<Column*> m_columns;
		std::list<Column*> m_columnsOrder;

		void setRowsCountOnPage(int count) {
			m_pageNav->setItemCountOnPage(count);
		}

		void setRowsCount(int count) {
			m_pageNav->setItemCount(count);
			m_pageNav->update();
		}

		int getCurrentPage() {
			return m_pageNav->getCurrentPage() - 1;
		}

		int getMaxRowsOnPage() {
			return m_pageNav->getItemCountOnPage();
		}

		bool isRowBefore(int rowIdx) {
			return rowIdx < getCurrentPage() * getMaxRowsOnPage();
		}

		bool isRowAfter(int rowIdx) {
			return rowIdx >= (getCurrentPage() + 1) * getMaxRowsOnPage();
		}

		const std::string& getSearchText() {
			return m_textBox->getInputValue();
		}

		virtual void onOrder(Column* column) { update(); };
		virtual void onSearch(const std::string& text) { update(); };

		void addColumn(Column* column)
		{
			m_columns.push_back(column);
			column->setParent(this);
			column->getLeftMouseClickEvent() += [&](Events::ISender* sender) {
				auto column = static_cast<Column*>(sender);
				if (column->m_order != Column::Order::Disabled) {
					column->nextOrder();
					if (column->m_order == Column::Order::Default)
						m_columnsOrder.remove(column);
					else if (column->m_order == Column::Order::Asc) {
						m_columnsOrder.push_front(column);
					}
					onOrder(column);
				}
			};
		}

		void buildHeader()
		{
			m_table->getHeader().clear();
			for (auto column : m_columns) {
				m_table->getHeader()
					.beginTD()
					.addItem(column)
					.endTD();
			}
		}

		Table::TR& beginRow()
		{
			return m_table->getBody().beginTR();
		}

		void clearTable() {
			m_table->getBody().clear();
		}
	};

	class TriggerTableView : public TableView
	{
	public:
		TriggerTableView(TriggerTable* triggerTable)
			: m_triggerTable(triggerTable)
		{
			addColumn(new Column((int)TriggerTable::Columns::CallId, "Call id"));
			addColumn(new Column((int)TriggerTable::Columns::TriggerId, "Trigger id", true));
			addColumn(new Column((int)TriggerTable::Columns::FunctionId, "Function name", true));
			buildHeader();
			update();
		}

		TriggerTable::Result getResult() {
			auto result = m_triggerTable->where([&](const TriggerTable::Tuple& tuple) {
				return std::get<(int)TriggerTable::Columns::FunctionId>(tuple).find(getSearchText()) != std::string::npos;
			});

			for (auto column : m_columnsOrder) {
				switch ((TriggerTable::Columns)column->m_idx)
				{
				case TriggerTable::Columns::TriggerId:
					result.orderBy<(int)TriggerTable::Columns::TriggerId>(column->isDescending());
					break;
				case TriggerTable::Columns::FunctionId:
					result.orderBy<(int)TriggerTable::Columns::FunctionId>(column->isDescending());
					break;
				}
			}

			return result;
		}

		void update() override {
			clearTable();

			auto list = getResult().getList();
			int rowidx = -1;
			int shownRowsCount = 0;
			for (auto idx : list) {
				rowidx++;
				if (isRowBefore(rowidx))
					continue;
				if (isRowAfter(rowidx))
					break;
				auto& row = *m_triggerTable->getRow(idx);
				auto& tr = beginRow();

				tr.beginTD()
					.text(std::to_string(std::get<(int)TriggerTable::Columns::CallId>(row)));
				tr.beginTD()
					.text(std::to_string(std::get<(int)TriggerTable::Columns::TriggerId>(row)));
				tr.beginTD()
					.text(std::get<(int)TriggerTable::Columns::FunctionId>(row));
				shownRowsCount++;
			}

			setRowsCount((int)list.size());
		}

		void onUpdate() override {
			if (++m_counter >= 300) {
				update();
				m_counter = 0;
			}
		}
	private:
		TriggerTable* m_triggerTable;
		int m_counter = 0;
	};
};


void test() {

}

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

			text("hello world!");
			
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
		public Events::OnHovered<HoverText>
	{
	public:
		ShortCut* m_cont;
		HoverText(const std::string& name)
			: Elements::Text::Text(name), Events::OnHovered<HoverText>(this, getWindow())
		{
			m_cont = new ShortCut;
		}

		void render() override {
			Elements::Text::Text::render();
			if (ImGui::IsItemHovered()) {
				if (m_lastStartHoveredTime == 0)
					m_lastStartHoveredTime = GetTickCount64();
				if (GetTickCount64() - m_lastStartHoveredTime > 200) {
					m_cont->setVisible();
				}
			}
			else {
				m_lastStartHoveredTime = 0;
			}
			m_cont->show();
			ImGui::SameLine();
			Elements::Text::Text::render();
		}

		void onHoveredIn() {
			m_cont->setVisible();
		}
	private:
		ULONGLONG m_lastStartHoveredTime;
	};



	class TypeViewValue : public Elements::Text::ColoredText
	{
	public:
		TypeViewValue()
			: Elements::Text::ColoredText("hover text", ColorRGBA(0xFFFFFFFF))
		{
		
		}

		~TypeViewValue() {
			if (m_valueEditor != nullptr)
				m_valueEditor->destroy();
		}

		Elements::Input::FilterText* M_TTTT;
		void render() override {
			Elements::Text::ColoredText::render();

			if (ImGui::IsItemClicked(0)) {
				if (m_valueEditor == nullptr) {
						m_valueEditor = new PopupContainer(false, 0);
						m_valueEditor->setParent(this);
						m_valueEditor->text("444");
						m_valueEditor->setVisible();
						m_valueEditor->setHideByClick(true);

						m_valueEditor->addItem(
							(M_TTTT = new Elements::Input::FilterText(""))
							->setCompare(true)
							->addWord("cat")
							->addWord("dogs")
							->addWord("car")
						);
				}
				else {
					m_valueEditor->setVisible();
				}
			}

			if (m_valueEditor != nullptr) {
				m_valueEditor->show();
			}
		}
	private:
		PopupContainer* m_valueEditor = nullptr;
	};



	class WindowTest : public IWindow
	{
	public:
		//bool m_selected
		Elements::Input::FilterText* M_TTTT;

		bool m_if = true;

		Elements::Input::Bool* input;
		WindowTest()
			: IWindow("ImGui window for test")
		{

			auto eventHandler = Events::Listener(
				std::function([&](Events::ISender* sender) {
					auto text = static_cast<Elements::Input::FilterText*>(sender);
					auto val = text->getInputValue();
					if (val == "lol") {
						throw Exception(text, "error occured.");
					}
				})
			);

			auto table = new TriggerTable;

			table->addRow(1, 10, "func 1");
			table->addRow(2, 11, "func 2");
			table->addRow(3, 101, "alloca");
			table->addRow(4, 31, "func 22");
			table->addRow(5, 31, "func mem");
			for(int i = 10; i < 1000; i ++)
				table->addRow(i, 50, "setPos");

			auto cnt = new Container;

			getMainContainer()
				//.addItem(new TypeViewValue)

				.addItem(new Widget::TriggerTableView(table))
				.newLine()
				.newLine();
			
			(*cnt)
				.beginTabBar("lol")
					.setFlags(ImGuiTabBarFlags_Reorderable)

					->as<TabBar>()
					.beginTabItem("first")
						
						.text("111")
					.end()

					.as<TabBar>()
					.beginTabItem("second")
						.text("222")
					.end()
				.end()


				.newLine()
				.newLine()
				.newLine()


				.beginIf(_condition(m_if))
					.text("6666")
				.as<Condition>()
				.beginElse()
					.text("8888")
				.end()

				.addItem(new Elements::Button::ButtonTag("testsssssssssssss", ColorRGBA(0xFF0000FF))).sameLine()
				.addItem(new Elements::Button::ButtonTag("2222", ColorRGBA(0xFFFF00FF)))
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
										(M_TTTT = new Elements::Input::FilterText("", eventHandler))
										->setCompare(true)
										->addWord("cat")
										->addWord("dogs")
										->addWord("car")
									)
				//.addItem(new MirrorItem(M_TTTT))
				
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
					if (ImGui::Button("click")) {
						ImGui::OpenPopup("lol2");
					}

					if (ImGui::BeginPopup("lol2"))
					{
						if (ImGui::TreeNode("Base"))
						{
							if (ImGui::Selectable("trigger 1")) {

							}

							if (ImGui::Selectable("trigger 2")) {

							}
							ImGui::TreePop();
						}
						ImGui::EndPopup();
					}

					
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

					/*ImGui::OpenPopup("lol");
					static bool op = true;
					if (ImGui::BeginPopupModal("lol", &op)) {
						ImGui::Text("loool");
						ImGui::EndPopup();
					}*/
				});
		}
	};

	class WinManager
	{
	public:
		static void registerWindows() {
			UI::WinManager::addWindow(new WindowTest);
			test();
		}

		static void addWindow(GUI::Window::IWindow* window) {

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
		
		//ImGui::PopFont();

		ImGui::Render();
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	}
};