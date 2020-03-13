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

			struct TriggerState
			{
				bool m_beforeFilter = false;
			};

			class Hook
			{
			public:
				Hook(CE::Function::FunctionDefinition* definition);

				inline std::list<Trigger*>& getTriggers() {
					return m_triggers;
				}

				inline CE::Hook::DynHook* getDynHook() {
					return &m_hook;
				}

				void addTrigger(Trigger* trigger) {
					m_triggers.push_back(trigger);
				}

				void removeTrigger(Trigger* trigger) {
					m_triggers.remove(trigger);
				}
			private:
				CE::Hook::DynHook m_hook;
				std::list<Trigger*> m_triggers;
			};

			class Trigger : public ITrigger
			{
			public:
				Trigger(int id, const std::string& name, const std::string& desc = "")
					: ITrigger(id, name, desc)
				{}

				Type getType() override {
					return Type::FunctionTrigger;
				}

				void addFilter(Filter::IFilter* filter) {
					m_filters.push_back(filter);
				}

				void removeFilter(Filter::IFilter* filter) {
					m_filters.remove(filter);
				}

			public:
				bool checkFilterBefore(CE::Hook::DynHook* hook) {
					for (auto& filter : m_filters) {
						if (filter->checkFilterBefore(hook)) {
							return true;
						}
					}
					return false;
				}

				bool checkFilterAfter(CE::Hook::DynHook* hook) {
					for (auto& filter : m_filters) {
						if (filter->checkFilterAfter(hook)) {
							return true;
						}
					}
					return false;
				}

				bool actionBefore(CE::Hook::DynHook* hook) {
					bool sendStat = false;
					bool notExecute = false;
					if (checkFilterBefore(hook)) {
						notExecute = m_notExecute;
						hook->getUserData<TriggerState>().m_beforeFilter = true;
						sendStat = true;
					}

					if (sendStat) {
						if (m_statCollector != nullptr) {
							m_statCollector->addBeforeCallInfo(this, hook);
						}
					}
					return !notExecute;
				}

				void actionAfter(CE::Hook::DynHook* hook) {
					bool sendStat = hook->getUserData<TriggerState>().m_beforeFilter;
					if (checkFilterAfter(hook)) {
						sendStat = true;
					}

					if (sendStat) {
						if (m_statCollector != nullptr) {
							m_statCollector->addAfterCallInfo(this, hook);
						}
					}
				}

				void setStatCollector(Stat::Function::Collector* collector) {
					m_statCollector = collector;
				}

				void setNotExecute(bool toggle) {
					m_notExecute = toggle;
				}

				void addHook(Hook* hook) {
					m_hooks.push_back(hook);
					hook->addTrigger(this);
				}

				auto& getFilters() {
					return m_filters;
				}
			private:
				Stat::Function::Collector* m_statCollector = nullptr;
				std::list<Filter::IFilter*> m_filters;
				std::list<Hook*> m_hooks;
				bool m_notExecute = false;
			};

			static bool callback_before(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
				bool exectute = true;
				for (auto trigger : func->getHook()->getTriggers()) {
					exectute &= trigger->actionBefore(hook);
				}

				/*	auto value1 = hook->getArgumentValue<uint64_t>(5);
					auto value2 = hook->getXmmArgumentValue<float>(2);
					auto value3 = hook->getXmmArgumentValue<float>(3);
					auto value4 = hook->getXmmArgumentValue<float>(4);*/

				return exectute;
			}

			static void callback_after(CE::Hook::DynHook* hook)
			{
				auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
				for (auto trigger : func->getHook()->getTriggers()) {
					trigger->actionAfter(hook);
				}
				//hook->setReturnValue(11);
			}
		};
	};
};