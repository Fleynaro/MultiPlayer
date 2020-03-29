#pragma once
#include "Filter.h"
#include <Statistic/Function.h>

namespace CE
{
	namespace Trigger
	{
		enum Type
		{
			FunctionTrigger
		};

		class ITrigger : public Desc
		{
		public:
			ITrigger(int id, std::string name, std::string desc = "")
				: Desc(id, name, desc)
			{}

			virtual Type getType() = 0;
		};

		class TriggerGroup
		{
		public:
			TriggerGroup(int id, std::string name, std::string desc = "")
				: m_desc(id, name, desc)
			{}

			void addTrigger(ITrigger* trigger) {
				m_triggers.push_back(trigger);
			}

			std::list<ITrigger*>& getTriggers() {
				return m_triggers;
			}

			Desc& getDesc() {
				return m_desc;
			}
		private:
			Desc m_desc;
			std::list<ITrigger*> m_triggers;
		};

		namespace Function
		{
			class Hook;
			class Trigger;
			class TableLog;

			struct TriggerState
			{
				bool m_beforeFilter = false;
			};

			class Hook
			{
			public:
				Hook(CE::Function::FunctionDefinition* definition);

				inline std::list<Trigger*>& getActiveTriggers() {
					return m_activeTriggers;
				}

				inline CE::Hook::DynHook* getDynHook() {
					return &m_hook;
				}

				inline CE::Function::FunctionDefinition* getFunctionDef() {
					return static_cast<CE::Function::FunctionDefinition*>(getDynHook()->getUserPtr());
				}

				void addActiveTrigger(Trigger* trigger) {
					//mutex
					if (m_activeTriggers.size() == 0) {
						m_hook.enable();
					}
					m_activeTriggers.push_back(trigger);
				}

				void removeActiveTrigger(Trigger* trigger) {
					//mutex
					m_activeTriggers.remove(trigger);

					if (m_activeTriggers.size() == 0) {
						m_hook.disable();
					}
				}
			private:
				CE::Hook::DynHook m_hook;
				std::list<Trigger*> m_activeTriggers;
			};

			class Trigger : public ITrigger
			{
			public:
				Trigger(int id, const std::string& name, const std::string& desc = "")
					: ITrigger(id, name, desc)
				{
					m_compositeFilter = new Filter::ConditionFilter(Filter::Id::Condition_AND);
				}

				~Trigger() {
					delete m_compositeFilter;
				}

				Type getType() override {
					return Type::FunctionTrigger;
				}
			public:
				bool actionBefore(CE::Hook::DynHook* hook);

				void actionAfter(CE::Hook::DynHook* hook);

				void setStatCollector(Stat::Function::Collector* collector) {
					m_statCollector = collector;
				}

				void setNotExecute(bool toggle) {
					m_notExecute = toggle;
				}

				bool isNotExecute() {
					return m_notExecute;
				}

				void addFunction(API::Function::Function* function) {
					m_functions.push_back(function);
				}

				void start() {
					setActiveState(true);
					m_isActive = true;
				}

				void stop() {
					setActiveState(false);
					m_isActive = false;
				}

				bool isActive() {
					return m_isActive;
				}

				Filter::ICompositeFilter* getFilters() {
					return m_compositeFilter;
				}

				auto& getFunctions() {
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
				Filter::ICompositeFilter* m_compositeFilter;
				std::list<API::Function::Function*> m_functions;
				bool m_notExecute = false;
				bool m_isActive = false;

				void setActiveState(bool state) {
					for (auto it : m_functions) {
						if (!it->getDefinition().hasHook())
							continue;
						if (state) {
							it->getDefinition().getHook()->addActiveTrigger(this);
						}
						else {
							it->getDefinition().getHook()->removeActiveTrigger(this);
						}
					}
				}
			};

			static bool callback_before(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
				bool exectute = true;
				for (auto trigger : func->getHook()->getActiveTriggers()) {
					exectute &= trigger->actionBefore(hook);
				}

				auto funcName = func->getDeclaration().getName();
				auto& signature = func->getDeclaration().getSignature();
				auto hookMethod = hook->getMethod();

				auto value1 = hook->getArgumentValue<uint64_t>(1);
				auto value2 = hook->getArgumentValue<uint64_t>(2);
				auto value3 = hook->getArgumentValue<uint64_t>(3);
				auto value4 = hook->getArgumentValue<uint64_t>(4);
				auto value5 = hook->getArgumentValue<uint64_t>(5);
				auto value6 = hook->getArgumentValue<uint64_t>(6);
				auto value7 = hook->getArgumentValue<uint64_t>(7);

				auto int_value1 = hook->getArgumentValue<int>(1);
				auto int_value2 = hook->getArgumentValue<int>(2);
				auto int_value3 = hook->getArgumentValue<int>(3);
				auto int_value4 = hook->getArgumentValue<int>(4);
				auto int_value5 = hook->getArgumentValue<int>(5);
				auto int_value6 = hook->getArgumentValue<int>(6);
				auto int_value7 = hook->getArgumentValue<int>(7);

				auto xmm_value1 = hook->getXmmArgumentValue<float>(1);
				auto xmm_value2 = hook->getXmmArgumentValue<float>(2);
				auto xmm_value3 = hook->getXmmArgumentValue<float>(3);
				auto xmm_value4 = hook->getXmmArgumentValue<float>(4);
				auto xmm_value5 = hook->getXmmArgumentValue<float>(5);
				auto xmm_value6 = hook->getXmmArgumentValue<float>(6);
				auto xmm_value7 = hook->getXmmArgumentValue<float>(7);
				auto xmm_value8 = hook->getXmmArgumentValue<float>(8);

				return exectute;
			}

			static void callback_after(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
				for (auto trigger : func->getHook()->getActiveTriggers()) {
					trigger->actionAfter(hook);
				}
				//hook->setReturnValue(11);

				auto retAddr = hook->getReturnAddress();
				auto retValue = hook->getReturnValue();
				auto xmm_retValue = hook->getXmmReturnValue<float>();

				int a = 5;
			}
		};
	};
};