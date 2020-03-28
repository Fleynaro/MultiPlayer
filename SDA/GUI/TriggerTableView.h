#pragma once
#include "GUI/Widgets/TableView.h"
#include <Trigger/TriggerTableLog.h>
#include "Project.h"

namespace GUI::Widget::TableViews
{
	using namespace CE::Trigger::Function;
	class TriggerTableView : public TableView
	{
	public:
		class Value
			: public Elements::Text::Text
		{
		public:
			Value(uint64_t value, void* addr, CE::Type::Type* type, CE::TypeManager* typeManager)
				: m_addr(addr), m_type(type), m_typeManager(typeManager), Elements::Text::Text(type->getViewValue(value))
			{}

			void render() override {
				Elements::Text::Text::render();

				if (m_addr != nullptr)
				{
					if (ImGui::IsItemHovered()) {
						ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
					}
					if (ImGui::IsItemClicked(0)) {
						if (m_valueEditor == nullptr) {
							if (Address(m_addr).canBeRead()) {
								m_valueEditor = new PopupContainer(false, 0);
								m_valueEditor->setParent(this);

								AddressValueEditor::Style style;
								style.m_typeSelector = true;
								style.m_protectSelector = false;
								style.m_pointerDereference = false;
								style.m_arrayItemSelector = true;
								style.m_changeValueByButton = false;
								style.m_dereference = true;
								auto editor = new AddressValueEditor(m_addr, m_type, style);
								editor->setTypeManager(m_typeManager);
								m_valueEditor->addItem(editor);
								m_valueEditor->setVisible();
								m_valueEditor->setHideByClick(true);
							}
						}
						else {
							m_valueEditor->setVisible();
						}
					}

					if (m_valueEditor != nullptr) {
						m_valueEditor->show();
					}
				}
			}

		private:
			CE::TypeManager* m_typeManager;
			PopupContainer* m_valueEditor = nullptr;
			void* m_addr;
			CE::Type::Type* m_type;
		};

		class ValueColContainer : public ColContainer
		{
		public:
			ValueColContainer()
				: ColContainer("")
			{}

			void addValue(Value* item)
			{
				addItem(item);

				m_text += item->getText() + ", ";
				if (m_text.length() < 40) {
					setName(getText());
				}
			}

			void onHeaderRender() override {
				if (ImGui::IsItemHovered()) {
					ImGui::SetTooltip(getText().c_str());
				}
			}

			std::string getText() {
				return m_text.substr(0, m_text.length() - 2);
			}
		private:
			std::string m_text;
		};

		enum Columms
		{
			c_Function,
			c_ElapsedTime,
			c_Arguments,
			c_Return,
			c_ReturnAddr
		};

		TriggerTableView(TableLog* triggerTable, Project* project)
			: m_triggerTable(triggerTable), m_project(project)
		{
			addColumn(new Column(c_Function, "Function", true));
			addColumn(new Column(c_ElapsedTime, "Elapsed time", true));
			addColumn(new Column(c_Arguments, "Arguments", true));
			addColumn(new Column(c_Return, "Return", true));
			addColumn(new Column(c_ReturnAddr, "Return address", true));
			buildHeader();
			update();
		}

		TableLog::Result getResult() {
			auto result = m_triggerTable->where([&](const TableLog::Tuple& row) {
				auto func = getFunction(row);
				if (func == nullptr)
					return false;
				if (getSearchText().length() == 0)
					return true;

				{
					auto& argValues = std::get<TableLog::ArgValues>(row);
					for (auto value : argValues) {
						if (value.isString() && Generic::String::Contains((char*)value.getRawData(), getSearchText()))
							return true;
					}
				}
				{
					auto& retValue = std::get<TableLog::RetValue>(row);
					if (retValue.isString() && Generic::String::Contains((char*)retValue.getRawData(), getSearchText()))
						return true;
				}
				return Generic::String::Contains(func->getFunction()->getName(), getSearchText());
				});

			result.orderBy([](const TableLog::Tuple& row1, const TableLog::Tuple& row2) {
				return std::get<TableLog::Time>(row1).m_startTime < std::get<TableLog::Time>(row2).m_startTime;
				});

			for (auto column : m_columnsOrder) {
				switch (column->m_idx)
				{
				case c_ReturnAddr:
					result.orderBy<TableLog::RetAddr>(column->isDescending());
					break;
				case c_Function:
					result.orderBy<TableLog::FunctionId>(column->isDescending());
					break;
				case c_ElapsedTime:
					result.orderBy([=](const TableLog::Tuple& row1, const TableLog::Tuple& row2) {
						return static_cast<bool>((std::get<TableLog::Time>(row1).getElapsedTime() < std::get<TableLog::Time>(row2).getElapsedTime()) ^ column->isDescending());
						});
					break;
				case c_Arguments:
					result.orderBy([=](const TableLog::Tuple& row1, const TableLog::Tuple& row2) {
						auto argValues1 = std::get<TableLog::ArgValues>(row1);
						auto argValues2 = std::get<TableLog::ArgValues>(row2);
						if (argValues1.size() == 0 || argValues2.size() == 0)
							return true;
						return static_cast<bool>((argValues1.begin()->m_rawValue < argValues2.begin()->m_rawValue) ^ column->isDescending());
						});
					break;
				case c_Return:
					result.orderBy([=](const TableLog::Tuple& row1, const TableLog::Tuple& row2) {
						auto& retValue1 = std::get<TableLog::RetValue>(row1);
						auto& retValue2 = std::get<TableLog::RetValue>(row2);
						return static_cast<bool>((retValue1.m_rawValue < retValue2.m_rawValue) ^ column->isDescending());
						});
					break;
				}
			}

			return result;
		}

		void update() override {
			clearTable();
			m_shownRows.clear();
			updateCurPage();
		}

		void updateCurPage() {
			auto list = getResult().getList();
			int rowidx = -1;
			int shownRowsCount = 0;
			for (auto idx : list) {
				rowidx++;
				if (isRowBefore(rowidx))
					continue;
				if (isRowAfter(rowidx))
					break;
				if (m_shownRows.count(idx) != 0)
					continue;

				auto& row = *m_triggerTable->getRow(idx);
				auto& tr = beginRow();

				auto func = getFunction(row);
				if (func == nullptr)
					return;

				m_shownRows.insert(idx);

				tr.beginTD()
					.text(func->getFunction()->getName());
				tr.beginTD()
					.text(std::to_string(std::get<TableLog::Time>(row).getElapsedTime()) + " ms");

				auto typeManager = m_project->getProgramExe()->getTypeManager();
				{
					auto& argValues = std::get<TableLog::ArgValues>(row);
					auto colCnt = new ValueColContainer;
					tr.beginTD().addItem(colCnt);
					for (auto value : argValues) {
						colCnt->addValue(new Value(
							value.m_rawValue,
							value.getRawData(),
							value.m_type,
							typeManager
						));
					}
				}
				{
					auto& retValue = std::get<TableLog::RetValue>(row);
					tr.beginTD()
						.addItem(new Value(
							retValue.m_rawValue,
							retValue.getRawData(),
							retValue.m_type,
							typeManager
						));
				}

				tr.beginTD()
					.text("0x" + Generic::String::NumberToHex((uint64_t)std::get<TableLog::RetAddr>(row)));
				shownRowsCount++;
			}

			setRowsCount((int)list.size());
		}

		CE::API::Function::Function* getFunction(const TableLog::Tuple& row) {
			return m_project->getProgramExe()->getFunctionManager()->getFunctionById(std::get<TableLog::FunctionId>(row));
		}

		void onUpdate() override {
			if (m_prevSize != m_triggerTable->size()) {
				updateCurPage();
				m_prevSize = m_triggerTable->size();
			}
		}
	private:
		TableLog* m_triggerTable;
		Project* m_project;
		int m_prevSize = 0;
		std::set<uint64_t> m_shownRows;
	};
};