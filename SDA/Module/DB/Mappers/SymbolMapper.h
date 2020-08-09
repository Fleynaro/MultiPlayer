#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Symbol/AbstractSymbol.h>

namespace CE {
	class SymbolManager;
};

namespace DB
{
	class SymbolMapper : public AbstractMapper
	{
	public:
		
		SymbolMapper(IRepository* repository)
			: AbstractMapper(repository)
		{}

		void loadAll() {

		}

		Id getNextId() override {
			auto& db = getManager()->getProgramModule()->getDB();
			return GenerateNextId(&db, "sda_symbols");
		}

		CE::SymbolManager* getManager() {
			return static_cast<CE::SymbolManager*>(m_repository);
		}
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override {

		}

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override {
			doUpdate(ctx, obj);
		}

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override {
			auto symbol = static_cast<CE::Symbol::AbstractSymbol*>(obj);
			SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_symbols (symbol_id, name, type_id, pointer_lvl, comment, save_id, ghidra_sync_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0)");
			query.bind(1, symbol->getId());
			bind(query, *symbol);
			query.bind(6, ctx->m_saveId);
			query.exec();
		}

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override {
			std::string action_query_text =
				ctx->m_notDelete ? "UPDATE sda_symbols SET deleted=1" : "DELETE FROM sda_symbols";
			Statement query(*ctx->m_db, action_query_text + " WHERE symbol_id=?1");
			query.bind(1, obj->getId());
			query.exec();
		}

	private:
		void bind(SQLite::Statement& query, CE::Symbol::AbstractSymbol& symbol) {
			query.bind(2, symbol.getName());
			query.bind(3, symbol.getType()->getId());
			query.bind(4, DataType::GetPointerLevelStr(symbol.getType()));
			query.bind(5, symbol.getComment());
		}
	};
};