#include "MemoryAreaMapper.h"
#include <Manager/MemoryAreaManager.h>
#include <Manager/SymbolManager.h>

using namespace DB;
using namespace CE;
using namespace Symbol;

SymbolTableMapper::SymbolTableMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void SymbolTableMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_mem_areas");
	load(&db, query);
	loadSymbolsForAllSymTables(&db);
}

Id SymbolTableMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_mem_areas");
}

SymbolTableManager* SymbolTableMapper::getManager() {
	return static_cast<SymbolTableManager*>(m_repository);
}

IDomainObject* SymbolTableMapper::doLoad(Database* db, SQLite::Statement& query) {
	int mem_area_id = query.getColumn("mem_area_id");
	auto type = (SymbolTable::SymbolTableType)(int)query.getColumn("type");
	int size = query.getColumn("size");

	auto memoryArea = new SymbolTable(getManager(), type, size);
	memoryArea->setId(mem_area_id);
	return memoryArea;
}

void SymbolTableMapper::loadSymbolsForAllSymTables(Database* db) {
	SQLite::Statement query(*db, "SELECT * FROM sda_mem_area_symbols");
	
	while (query.executeStep())
	{
		int symbol_id = query.getColumn("symbol_id");
		int mem_area_id = query.getColumn("mem_area_id");
		int64_t offset = query.getColumn("offset");

		auto memoryArea = getManager()->getSymbolTableById(mem_area_id);
		if (memoryArea == nullptr)
			continue;
		auto symbol = getManager()->getProgramModule()->getSymbolManager()->getSymbolById(symbol_id);
		memoryArea->addSymbol(symbol, offset);
		if (auto memSymbol = dynamic_cast<MemorySymbol*>(symbol))
			memSymbol->setOffset(offset);
	}
}

void SymbolTableMapper::saveSymbolsForSymTable(TransactionContext* ctx, SymbolTable* memoryArea) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_mem_area_symbols WHERE mem_area_id=?1");
		query.bind(1, memoryArea->getId());
		query.exec();
	}

	{
		for (auto& it : memoryArea->getSymbols()) {
			auto symbol = it.second;
			auto offset = it.first;
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_mem_area_symbols (symbol_id, mem_area_id, offset) VALUES(?1, ?2, ?3)");
			query.bind(1, symbol->getId());
			query.bind(2, memoryArea->getId());
			query.bind(3, offset);
			query.exec();
		}
	}
}

void SymbolTableMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void SymbolTableMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto memoryArea = static_cast<SymbolTable*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_mem_areas (mem_area_id, type, size, save_id) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, memoryArea->getId());
	bind(query, *memoryArea);
	query.bind(4, ctx->m_saveId);
	query.exec();
	saveSymbolsForSymTable(ctx, memoryArea);
}

void SymbolTableMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_mem_areas SET deleted=1" : "DELETE FROM sda_mem_areas";
	Statement query(*ctx->m_db, action_query_text + " WHERE mem_area_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void SymbolTableMapper::bind(SQLite::Statement& query, SymbolTable& memoryArea) {
	query.bind(2, memoryArea.getType());
	query.bind(3, memoryArea.getSize());
}
