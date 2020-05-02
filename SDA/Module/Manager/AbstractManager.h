#pragma once
#include <DB/AbstractMapper.h>
#include "ProgramModule.h"

namespace CE
{
	class AbstractManager
	{
	public:
		AbstractManager(ProgramModule* programModule)
			: m_programModule(programModule)
		{}
		
		ProgramModule* getProgramModule() {
			return m_programModule;
		}
	private:
		ProgramModule* m_programModule;
	};

	class AbstractItemManager : public AbstractManager, public DB::IRepository
	{
	public:
		AbstractItemManager(ProgramModule* programModule)
			: AbstractManager(programModule)
		{}

		void onLoaded(DB::DomainObject* obj) override {
			m_items.insert(std::make_pair(obj->getId(), obj));
		}

		void onChangeBeforeCommit(DB::DomainObject* obj, ChangeType type) override {
			switch (type)
			{
			case Inserted:
				m_items.insert(std::make_pair(obj->getId(), obj));
				break;
			case Removed:
				m_items.erase(obj->getId());
				break;
			}
		}

		void onChangeAfterCommit(DB::DomainObject* obj, ChangeType type) override {
		}
		
		DB::DomainObject* find(DB::Id id) override {
			if (m_items.find(id) == m_items.end())
				return nullptr;
			return m_items[id];
		}

		int getItemsCount() {
			return (int)m_items.size();
		}
	protected:
		using ItemMapType = std::map<DB::Id, DB::DomainObject*>;
		ItemMapType m_items;
	};

	namespace API
	{
		class IItemDB
		{
		public:
			virtual void lock() = 0;
			virtual void unlock() = 0;
			virtual void save() = 0;
		};

		class ItemDB : public IItemDB
		{
		public:
			void lock() override {
				if (m_locked)
					return;
				m_mutex.lock();
				m_locked = true;
			}

			void unlock() override {
				m_mutex.unlock();
				m_locked = false;
			}

			void change(std::function<void()> func) {
				lock();
				func();
				unlock();
			}

			void changeAndSave(std::function<void()> func) {
				lock();
				func();
				save();
				unlock();
			}
		private:
			std::mutex m_mutex;
			bool m_locked = false;
		};
	};
};