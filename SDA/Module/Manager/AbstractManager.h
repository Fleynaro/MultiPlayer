#pragma once
#include <DB/AbstractMapper.h>
#include "ProgramModule.h"
#include <Utils/Iterator.h>

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
		using ItemMapType = std::map<DB::Id, DB::IDomainObject*>;
		template<typename T = DB::DomainObject>
		class AbstractIterator : public IIterator<T*>
		{
		public:
			AbstractIterator(AbstractItemManager* manager)
				: m_iterator(manager->m_items.begin()), m_end(manager->m_items.end())
			{}

			bool hasNext() override {
				return m_iterator != m_end;
			}

			T* next() override {
				return static_cast<T*>((m_iterator++)->second);
			}
		private:
			ItemMapType::iterator m_iterator;
			ItemMapType::iterator m_end;
		};

		AbstractItemManager(ProgramModule* programModule)
			: AbstractManager(programModule)
		{}

		void onLoaded(DB::IDomainObject* obj) override {
			m_items.insert(std::make_pair(obj->getId(), obj));
		}

		void onChangeBeforeCommit(DB::IDomainObject* obj, ChangeType type) override {
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

		void onChangeAfterCommit(DB::IDomainObject* obj, ChangeType type) override {
		}
		
		DB::IDomainObject* find(DB::Id id) override {
			if (m_items.find(id) == m_items.end())
				return nullptr;
			return m_items[id];
		}

		int getItemsCount() {
			return (int)m_items.size();
		}
	protected:
		ItemMapType m_items;
	};
};