#include "SymbolMapper.h"
#include <Code/Symbol/Symbol.h>
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>

using namespace DB;
using namespace CE;
using namespace Symbol;

SymbolMapper::SymbolMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void SymbolMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_symbols");
	load(&db, query);
}

Id SymbolMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_symbols");
}

SymbolManager* SymbolMapper::getManager() {
	return static_cast<SymbolManager*>(m_repository);
}

IDomainObject* SymbolMapper::doLoad(Database* db, SQLite::Statement& query) {
	int symbol_id = query.getColumn("symbol_id");
	auto type = (Symbol::Type)(int)query.getColumn("type");
	std::string name = query.getColumn("name");
	std::string comment = query.getColumn("comment");

	auto dataType = getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("type_id"));
	if (dataType == nullptr) {
		dataType = getManager()->getProgramModule()->getTypeManager()->getDefaultType();
	}
	auto dataTypeUnit = DataType::GetUnit(dataType, query.getColumn("pointer_lvl"));

	AbstractSymbol* symbol = nullptr;
	switch (type)
	{
	case FUNCTION:
		symbol = new FunctionSymbol(getManager(), dataTypeUnit, name, comment);
		break;
	case GLOBAL_VAR:
		symbol = new GlobalVarSymbol(getManager(), -1, dataTypeUnit, name, comment);
		break;
	case LOCAL_INSTR_VAR:
		symbol = new LocalInstrVarSymbol(getManager(), dataTypeUnit, name, comment);
		break;
	case LOCAL_STACK_VAR:
		symbol = new LocalStackVarSymbol(getManager(), -1, dataTypeUnit, name, comment);
		break;
	case FUNC_PARAMETER:
		symbol = new FuncParameterSymbol(getManager(), dataTypeUnit, name, comment);
		break;
	}

	symbol->setId(symbol_id);
	return symbol;
}

void SymbolMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void SymbolMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto symbol = static_cast<AbstractSymbol*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_symbols (symbol_id, type, name, type_id, pointer_lvl, comment, save_id, ghidra_sync_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)");
	query.bind(1, symbol->getId());
	bind(query, *symbol);
	query.bind(7, ctx->m_saveId);
	query.exec();
}

void SymbolMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_symbols SET deleted=1" : "DELETE FROM sda_symbols";
	Statement query(*ctx->m_db, action_query_text + " WHERE symbol_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void SymbolMapper::bind(SQLite::Statement& query, AbstractSymbol& symbol) {
	query.bind(2, symbol.getType());
	query.bind(3, symbol.getName());
	query.bind(4, symbol.getDataType()->getId());
	query.bind(5, DataType::GetPointerLevelStr(symbol.getDataType()));
	query.bind(6, symbol.getComment());
}
