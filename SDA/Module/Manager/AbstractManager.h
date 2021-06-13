#pragma once
#include <DB/AbstractMapper.h>
#include <Project.h>
#include <Utils/Iterator.h>

namespace CE
{
	class AbstractManager
	{
	public:
		AbstractManager(Project* project);
		
		Project* getProject();
	private:
		Project* m_project;
	};

	class AbstractItemManager : public AbstractManager, public DB::IRepository
	{
	protected:
		// exceptions
		class ItemNotFoundException : public std::exception {
		public: ItemNotFoundException() : std::exception("item in manager not found") {}
		};
	public:
		// factory
		class AbstractFactory
		{
		protected:
			bool m_generateId;

			AbstractFactory(bool generateId)
				: m_generateId(generateId)
			{}
		};

		// iterator
		using ItemMapType = std::map<DB::Id, DB::IDomainObject*>;
		template<typename T = DB::IDomainObject>
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
				return dynamic_cast<T*>((m_iterator++)->second);
			}
		private:
			ItemMapType::iterator m_iterator;
			ItemMapType::iterator m_end;
		};

		AbstractItemManager(Project* programModule);

		void onLoaded(DB::IDomainObject* obj) override;

		void onChangeBeforeCommit(DB::IDomainObject* obj, ChangeType type) override;

		void onChangeAfterCommit(DB::IDomainObject* obj, ChangeType type) override;
		
		DB::IDomainObject* find(DB::Id id) override;

		int getItemsCount();
	protected:
		ItemMapType m_items;
	};
};