#include "FunctionDefMapper.h"
#include <Manager/FunctionDefManager.h>
#include <Manager/ProcessModuleManager.h>
#include <Manager/MemoryAreaManager.h>
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>
#include <GhidraSync/Mappers/GhidraFunctionDefMapper.h>

using namespace DB;
using namespace CE;

FunctionDefMapper::FunctionDefMapper(CE::FunctionManager* repository)
	: AbstractMapper(repository)
{}

void FunctionDefMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_functions WHERE deleted=0");
	load(&db, query);
}

Id FunctionDefMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_functions");
}

CE::FunctionManager* FunctionDefMapper::getManager() {
	return static_cast<CE::FunctionManager*>(m_repository);
}

IDomainObject* FunctionDefMapper::doLoad(Database* db, SQLite::Statement& query) {
	int func_id = query.getColumn("func_id");
	int signature_id = query.getColumn("signature_id");
	int func_symbol_id = query.getColumn("func_symbol_id");
	int module_id = query.getColumn("module_id");
	int stack_mem_area_id = query.getColumn("stack_mem_area_id");
	int is_exported = query.getColumn("exported");

	auto symbol = dynamic_cast<Symbol::FunctionSymbol*>(getManager()->getProgramModule()->getSymbolManager()->getSymbolById(func_symbol_id));
	auto signature = dynamic_cast<DataType::Signature*>(getManager()->getProgramModule()->getTypeManager()->getTypeById(signature_id));
	auto module = getManager()->getProgramModule()->getProcessModuleManager()->getProcessModuleById(module_id);

	auto function =
		new Function::FunctionDefinition(
			getManager(),
			symbol,
			module,
			AddressRangeList(),
			signature
		);

	if (stack_mem_area_id) {
		auto stack_mem_area = getManager()->getProgramModule()->getMemoryAreaManager()->getMemoryAreaById(stack_mem_area_id);
		if (stack_mem_area != nullptr) {
			function->setStackMemoryArea(stack_mem_area);
		}
	}
	
	function->setId(func_id);
	function->setGhidraMapper(getManager()->m_ghidraFunctionDefMapper);
	loadFunctionRanges(db, *function);
	return function;
}

void FunctionDefMapper::loadFunctionRanges(Database* db, CE::Function::FunctionDefinition& definition) {
	SQLite::Statement query(*db, "SELECT * FROM sda_func_ranges WHERE func_id=?1 GROUP BY order_id");
	query.bind(1, definition.getId());

	while (query.executeStep())
	{
		definition.addRange(AddressRange(
			definition.getProcessModule()->toAbsAddr(query.getColumn("min_offset")),
			definition.getProcessModule()->toAbsAddr(query.getColumn("max_offset"))
		));
	}
}

void FunctionDefMapper::saveFunctionRanges(TransactionContext* ctx, CE::Function::FunctionDefinition& definition) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_func_ranges WHERE func_id=?1");
		query.bind(1, definition.getId());
		query.exec();
	}

	{
		int order_id = 0;
		for (auto& range : definition.getAddressRangeList()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_func_ranges (func_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, definition.getId());
			query.bind(2, order_id);
			query.bind(3, definition.getProcessModule()->toRelAddr(range.getMinAddress()));
			query.bind(4, definition.getProcessModule()->toRelAddr(range.getMaxAddress()));
			query.exec();
			order_id++;
		}
	}
}

void FunctionDefMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void FunctionDefMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto& def = *static_cast<CE::Function::FunctionDefinition*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_functions (func_id, func_symbol_id, signature_id, module_id, stack_mem_area_id, exported, save_id)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
	query.bind(1, def.getId());
	bind(query, def);
	query.bind(7, ctx->m_saveId);
	query.exec();
	saveFunctionRanges(ctx, def);
}

void FunctionDefMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_functions SET deleted=1" : "DELETE FROM sda_functions";
	Statement query(*ctx->m_db, action_query_text + " WHERE func_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionDefMapper::bind(SQLite::Statement& query, CE::Function::FunctionDefinition& def) {
	query.bind(2, def.getFunctionSymbol()->getId());
	query.bind(3, def.getSignature()->getId());
	query.bind(4, def.getProcessModule()->getId());
	query.bind(5, def.getStackMemoryArea() ? def.getStackMemoryArea()->getId() : 0);
	query.bind(6, def.isExported());
}
