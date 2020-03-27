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
		enum Columms
		{
			c_Function,
			c_ElapsedTime,
			c_Arguments,
			c_Return
		};

		TriggerTableView(TableLog* triggerTable, Project* project)
			: m_triggerTable(triggerTable), m_project(project)
		{
			addColumn(new Column(c_Function, "Function", true));
			addColumn(new Column(c_ElapsedTime, "Elapsed time"));
			addColumn(new Column(c_Arguments, "Arguments"));
			addColumn(new Column(c_Return, "Return"));
			buildHeader();
			update();
		}

		TableLog::Result getResult() {
			auto result = m_triggerTable->where([&](const TableLog::Tuple& row) {
				auto func = getFunction(row);
				if (func == nullptr)
					return false;
				return getSearchText().size() == 0 || Generic::String::Contains(func->getFunction()->getName(), getSearchText());
				});

			result.orderBy([](const TableLog::Tuple& row1, const TableLog::Tuple& row2) {
				return std::get<TableLog::Time>(row1).m_startTime < std::get<TableLog::Time>(row2).m_startTime;
				});

			for (auto column : m_columnsOrder) {
				switch (column->m_idx)
				{
				case c_Function:
					result.orderBy<TableLog::FunctionId>(column->isDescending());
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

				auto func = getFunction(row);
				if (func == nullptr)
					return;

				tr.beginTD()
					.text(func->getFunction()->getName());
				tr.beginTD()
					.text(std::to_string(std::get<TableLog::Time>(row).getElapsedTime()) + " ms");
				tr.beginTD()
					.text("");
				tr.beginTD()
					.text("");
				shownRowsCount++;
			}

			setRowsCount((int)list.size());
		}

		CE::API::Function::Function* getFunction(const TableLog::Tuple& row) {
			return m_project->getProgramExe()->getFunctionManager()->getFunctionById(std::get<TableLog::FunctionId>(row));
		}

		void onUpdate() override {
			if (++m_counter >= 300) {
				update();
				m_counter = 0;
			}
		}
	private:
		TableLog* m_triggerTable;
		Project* m_project;
		int m_counter = 0;
	};
};