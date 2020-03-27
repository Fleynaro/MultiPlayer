#pragma once
#include "Shared/GUI/Items/IWidget.h"
#include "Shared/GUI/Widgets/PageNavigation.h"

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
};