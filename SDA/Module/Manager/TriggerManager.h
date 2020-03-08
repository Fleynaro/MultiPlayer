#pragma once
#include "AbstractManager.h"
#include <Trigger/Trigger.h>

namespace CE
{
	class TriggerManager : public AbstractManager
	{
	public:
		using TriggerDict = std::map<int, Trigger::ITrigger*>;

		TriggerManager(ProgramModule* sda)
			: AbstractManager(sda)
		{}

		void saveTrigger(Trigger::ITrigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();

			{
				SQLite::Statement query(db, "REPLACE INTO sda_triggers(id, type, name, desc) VALUES(?1, ?2, ?3, ?4)");
				query.bind(1, trigger->getId());
				query.bind(2, trigger->getType());
				query.bind(3, trigger->getName());
				query.bind(4, trigger->getDesc());
				query.exec();
			}

			if (trigger->getType() == Trigger::FunctionTrigger) {
				saveFiltersForFuncTrigger(static_cast<Trigger::Function::Trigger*>(trigger));
			}
		}

		void saveFiltersForFuncTrigger(Trigger::Function::Trigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_func_trigger_filters WHERE trigger_id=?1");
				query.bind(1, trigger->getId());
				query.exec();
			}

			{
				for (const auto& filter : trigger->getFilters()) {
					BitStream bs;
					filter->serialize(bs);

					SQLite::Statement query(db, "INSERT INTO sda_func_trigger_filters (trigger_id, filter_id, data) VALUES(?1, ?2, ?3)");
					query.bind(1, trigger->getId());
					query.bind(2, (int)filter->getId());
					query.bind(3, bs.getData(), bs.getSize());
					query.exec();
				}
			}

			transaction.commit();
		}

		void loadFiltersForFuncTrigger(Trigger::Function::Trigger* trigger)
		{
			using namespace SQLite;
			using namespace Trigger::Function::Filter;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT filter_id,data FROM sda_func_trigger_filters WHERE trigger_id=?1");
			query.bind(1, trigger->getId());

			while (query.executeStep())
			{
				IFilter* filter = nullptr;
				auto filter_id = (Id)(int)query.getColumn("filter_id");

				switch (filter_id)
				{
				case Id::Empty:
					filter = new Empty;
					break;
				case Id::Object:
					filter = new Object;
					break;
				case Id::Argument:
					filter = new Cmp::Argument;
					break;
				case Id::ReturnValue:
					filter = new Cmp::RetValue;
					break;
				}

				BitStream bs;
				bs.write(query.getColumn("data").getBlob(), query.getColumn("data").getBytes());
				bs.resetPointer();
				filter->deserialize(bs);

				trigger->addFilter(filter);
			}
		}

		void removeTrigger(Trigger::ITrigger* trigger) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_triggers WHERE id=?1");
			query.bind(1, trigger->getId());
			query.exec();

			switch (trigger->getType())
			{
			case Trigger::FunctionTrigger:
				auto tr = static_cast<Trigger::Function::Trigger*>(trigger);
				tr->getFilters().clear();
				saveFiltersForFuncTrigger(tr);
				break;
			}

			auto it = m_triggers.find(trigger->getId());
			if (it != m_triggers.end()) {
				m_triggers.erase(it);
			}
		}

		int getNewId() {
			int id = 1;
			while (m_triggers.find(id) != m_triggers.end())
				id++;
			return id;
		}

		Trigger::Function::Trigger* createFunctionTrigger(std::string name, std::string desc = "") {
			int id = getNewId();
			auto trigger = new Trigger::Function::Trigger(id, name, desc);
			m_triggers[id] = trigger;
			return trigger;
		}

		void loadTriggers()
		{
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_triggers");

			while (query.executeStep())
			{
				Trigger::ITrigger* trigger = nullptr;

				int type = query.getColumn("type");
				switch ((Trigger::Type)type)
				{
				case Trigger::FunctionTrigger:
					trigger = new Trigger::Function::Trigger(
						query.getColumn("id"),
						query.getColumn("name"),
						query.getColumn("desc")
					);
					loadFiltersForFuncTrigger(static_cast<Trigger::Function::Trigger*>(trigger));
					break;
				}

				if (trigger != nullptr) {
					addTrigger(trigger);
				}
			}
		}

		TriggerDict& getTriggers() {
			return m_triggers;
		}

		void addTrigger(Trigger::ITrigger* trigger) {
			m_triggers.insert(std::make_pair(trigger->getId(), trigger));
		}

		inline Trigger::ITrigger* getTriggerById(int trigger_id) {
			if (m_triggers.find(trigger_id) == m_triggers.end())
				return nullptr;
			return m_triggers[trigger_id];
		}
	private:
		TriggerDict m_triggers;
	};


	class TriggerGroupManager : public AbstractManager
	{
	public:
		using TriggerGroupDict = std::map<int, Trigger::TriggerGroup*>;

		TriggerGroupManager(ProgramModule* sda)
			: AbstractManager(sda)
		{}

		void saveTriggerGroup(Trigger::TriggerGroup* group) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();

			{
				SQLite::Statement query(db, "REPLACE INTO sda_trigger_groups(group_id, name, desc) VALUES(?1, ?2, ?3)");
				query.bind(1, group->getDesc().getId());
				query.bind(2, group->getDesc().getName());
				query.bind(3, group->getDesc().getDesc());
				query.exec();
			}

			saveTriggersForGroup(group);
		}

		void removeTriggerGroup(Trigger::TriggerGroup* group) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "DELETE FROM sda_trigger_groups WHERE group_id=?1");
			query.bind(1, group->getDesc().getId());
			query.exec();

			group->getTriggers().clear();
			saveTriggersForGroup(group);

			auto it = m_triggerGroups.find(group->getDesc().getId());
			if (it != m_triggerGroups.end()) {
				m_triggerGroups.erase(it);
			}
		}

		void loadTriggerGroups()
		{
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT * FROM sda_trigger_groups");

			while (query.executeStep())
			{
				auto group = new Trigger::TriggerGroup(
					query.getColumn("group_id"),
					query.getColumn("name"),
					query.getColumn("desc")
				);
				addTriggerGroup(group);
				loadTriggersForGroup(group);
			}
		}

		void saveTriggersForGroup(Trigger::TriggerGroup* group) {
			using namespace SQLite;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Transaction transaction(db);

			{
				SQLite::Statement query(db, "DELETE FROM sda_trigger_group_triggers WHERE group_id=?1");
				query.bind(1, group->getDesc().getId());
				query.exec();
			}

			{
				for (const auto& trigger : group->getTriggers()) {
					SQLite::Statement query(db, "INSERT INTO sda_trigger_group_triggers (group_id, trigger_id) VALUES(?1, ?2)");
					query.bind(1, group->getDesc().getId());
					query.bind(2, trigger->getId());
					query.exec();
				}
			}

			transaction.commit();
		}

		void loadTriggersForGroup(Trigger::TriggerGroup* group)
		{
			using namespace SQLite;
			using namespace Trigger::Function::Filter;

			SQLite::Database& db = getProgramModule()->getDB();
			SQLite::Statement query(db, "SELECT trigger_id FROM sda_trigger_group_triggers WHERE group_id=?1");
			query.bind(1, group->getDesc().getId());

			while (query.executeStep())
			{
				auto trigger = getProgramModule()->getTriggerManager()->getTriggerById(query.getColumn("trigger_id"));
				if(trigger != nullptr)
					group->addTrigger(trigger);
			}
		}

		TriggerGroupDict& getTriggerGroups() {
			return m_triggerGroups;
		}

		void addTriggerGroup(Trigger::TriggerGroup* group) {
			m_triggerGroups.insert(std::make_pair(group->getDesc().getId(), group));
		}

		inline Trigger::TriggerGroup* getTriggerGroupById(int group_id) {
			if (m_triggerGroups.find(group_id) == m_triggerGroups.end())
				return nullptr;
			return m_triggerGroups[group_id];
		}
	private:
		TriggerGroupDict m_triggerGroups;
	};
};