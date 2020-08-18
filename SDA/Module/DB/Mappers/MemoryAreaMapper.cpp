#include "MemoryAreaMapper.h"
#include <Manager/MemoryAreaManager.h>
#include <Manager/SymbolManager.h>

using namespace DB;
using namespace CE;
using namespace Symbol;

MemoryAreaMapper::MemoryAreaMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void MemoryAreaMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_mem_areas");
	load(&db, query);
	loadSymbolsForAllMemAreas(&db);
}

Id MemoryAreaMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_mem_areas");
}

MemoryAreaManager* MemoryAreaMapper::getManager() {
	return static_cast<MemoryAreaManager*>(m_repository);
}

IDomainObject* MemoryAreaMapper::doLoad(Database* db, SQLite::Statement& query) {
	int mem_area_id = query.getColumn("mem_area_id");
	auto type = (MemoryArea::MemoryAreaType)(int)query.getColumn("type");
	int size = query.getColumn("size");

	auto memoryArea = new MemoryArea(getManager(), type, size);
	memoryArea->setId(mem_area_id);
	return memoryArea;
}

void MemoryAreaMapper::loadSymbolsForAllMemAreas(Database* db) {
	SQLite::Statement query(*db, "SELECT * FROM sda_mem_area_symbols");
	
	while (query.executeStep())
	{
		int symbol_id = query.getColumn("symbol_id");
		int mem_area_id = query.getColumn("mem_area_id");
		int offset = query.getColumn("offset");

		auto memoryArea = getManager()->getMemoryAreaById(mem_area_id);
		if (memoryArea == nullptr)
			continue;
		auto symbol = getManager()->getProgramModule()->getSymbolManager()->getSymbolById(symbol_id);
		if (auto memSymbol = dynamic_cast<Symbol::MemorySymbol*>(symbol)) {
			memoryArea->addSymbol(memSymbol, offset);
		}
	}
}

void MemoryAreaMapper::saveSymbolsForMemArea(TransactionContext* ctx, MemoryArea* memoryArea) {
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

void MemoryAreaMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void MemoryAreaMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto memoryArea = static_cast<MemoryArea*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_mem_areas (mem_area_id, type, size, save_id) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, memoryArea->getId());
	bind(query, *memoryArea);
	query.bind(4, ctx->m_saveId);
	query.exec();
	saveSymbolsForMemArea(ctx, memoryArea);
}

void MemoryAreaMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_mem_areas SET deleted=1" : "DELETE FROM sda_mem_areas";
	Statement query(*ctx->m_db, action_query_text + " WHERE mem_area_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void MemoryAreaMapper::bind(SQLite::Statement& query, MemoryArea& memoryArea) {
	query.bind(2, memoryArea.getType());
	query.bind(3, memoryArea.getSize());
}
