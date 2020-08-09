#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace CE {
	class MemoryAreaManager;
};

namespace DB
{
	class MemoryAreaMapper : public AbstractMapper
	{
	public:

		MemoryAreaMapper(IRepository* repository)
			: AbstractMapper(repository)
		{}

		void loadAll() {

		}

		Id getNextId() override {
			auto& db = getManager()->getProgramModule()->getDB();
			return GenerateNextId(&db, "sda_mem_areas");
		}

		CE::MemoryAreaManager* getManager() {
			return static_cast<CE::MemoryAreaManager*>(m_repository);
		}
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override {

		}

		void loadSymbolsForMemArea(Database* db, CE::Symbol::MemoryArea* memoryArea) {
			
		}

		void saveSymbolsForMemArea(TransactionContext* ctx, CE::Symbol::MemoryArea* memoryArea) {
			
		}

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override {
			doUpdate(ctx, obj);
		}

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override {
			auto memoryArea = static_cast<CE::Symbol::MemoryArea*>(obj);
			SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_mem_areas (mem_area_id, type, size, save_id) VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, memoryArea->getId());
			bind(query, *memoryArea);
			query.bind(4, ctx->m_saveId);
			query.exec();
		}

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override {
			std::string action_query_text =
				ctx->m_notDelete ? "UPDATE sda_mem_areas SET deleted=1" : "DELETE FROM sda_mem_areas";
			Statement query(*ctx->m_db, action_query_text + " WHERE mem_area_id=?1");
			query.bind(1, obj->getId());
			query.exec();
		}

	private:
		void bind(SQLite::Statement& query, CE::Symbol::MemoryArea& memoryArea) {
			query.bind(2, memoryArea.getType());
			query.bind(3, memoryArea.getSize());
		}
	};
};