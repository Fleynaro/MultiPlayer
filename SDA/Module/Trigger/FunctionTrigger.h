#pragma once
#include "AbstractTrigger.h"
#include "FunctionFilterFactory.h"
#include "FunctionTriggerHook.h"
#include <Statistic/Function/Collector/FunctionStatCollector.h>

namespace CE::Trigger::Function
{
	struct TriggerState
	{
		bool m_beforeFilter = false;
	};

	class TableLog;
	class Trigger : public AbstractTrigger
	{
	public:
		Trigger(int id, const std::string& name, const std::string& desc = "");

		~Trigger();

		Type getType() override;

		bool actionBefore(CE::Hook::DynHook* hook);

		void actionAfter(CE::Hook::DynHook* hook);

		void setStatCollector(CE::Stat::Function::Collector* collector);

		void setNotExecute(bool toggle);

		bool isNotExecute();

		void addFunction(API::Function::Function* function);

		void start();

		void stop();

		bool isActive();

		Filter::AbstractCompositeFilter* getFilters();

		std::list<CE::API::Function::Function*>& getFunctions() {
			return m_functions;
		}

		TableLog* getTableLog() {
			return m_tableLog;
		}

		void setTableLogEnable(bool toggle);

		bool m_sendStatAnyway = false;
		Stat::Function::Collector* m_statCollector = nullptr;
	private:
		TableLog* m_tableLog = nullptr;
		Filter::AbstractCompositeFilter* m_compositeFilter;
		std::list<API::Function::Function*> m_functions;
		bool m_notExecute = false;
		bool m_isActive = false;

		void setActiveState(bool state);
	};

	bool callback_before(CE::Hook::DynHook* hook);

	void callback_after(CE::Hook::DynHook* hook);
};