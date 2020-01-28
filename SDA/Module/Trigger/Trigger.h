#pragma once
#include "Filter.h"
#include <Statistic/Statistic.h>

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
				Trigger(int id, std::string name, std::string desc = "")
					: ITrigger(id, name, desc)
				{}

				Type getType() override {
					return Type::FunctionTrigger;
				}

				std::string getName() override {
					return "Function trigger";
				}

				std::string getDesc() override {
					return "Function trigger need for garbaging statistic and filtering function calls.";
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
						if (m_statArgManager != nullptr) {
							m_statArgManager->add(this, hook);
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
						if (m_statRetManager != nullptr) {
							m_statRetManager->add(this, hook);
						}
					}
				}

				void setStatArgManager(Stat::Function::Args::Manager* manager) {
					m_statArgManager = manager;
				}

				void setStatRetManager(Stat::Function::Ret::Manager* manager) {
					m_statRetManager = manager;
				}

				void setNotExecute(bool toggle) {
					m_notExecute = toggle;
				}

				auto& getFilters() {
					return m_filters;
				}
			private:
				Stat::Function::Args::Manager* m_statArgManager = nullptr;
				Stat::Function::Ret::Manager* m_statRetManager = nullptr;
				std::list<Filter::IFilter*> m_filters;
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