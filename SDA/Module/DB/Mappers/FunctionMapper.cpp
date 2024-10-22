#include "FunctionMapper.h"
#include <Manager/FunctionManager.h>
#include <Manager/ProcessModuleManager.h>
#include <Manager/MemoryAreaManager.h>
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>
#include <GhidraSync/Mappers/GhidraFunctionMapper.h>

using namespace DB;
using namespace CE;

FunctionMapper::FunctionMapper(CE::FunctionManager* repository)
	: AbstractMapper(repository)
{}

void FunctionMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_functions WHERE deleted=0");
	load(&db, query);
	loadFunctionRanges(&db);
}

Id FunctionMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_functions");
}

CE::FunctionManager* FunctionMapper::getManager() {
	return static_cast<CE::FunctionManager*>(m_repository);
}

IDomainObject* FunctionMapper::doLoad(Database* db, SQLite::Statement& query) {
	int func_id = query.getColumn("func_id");
	int signature_id = query.getColumn("signature_id");
	int func_symbol_id = query.getColumn("func_symbol_id");
	int module_id = query.getColumn("module_id");
	int stack_mem_area_id = query.getColumn("stack_mem_area_id");
	int body_mem_area_id = query.getColumn("body_mem_area_id");
	int is_exported = query.getColumn("exported");

	auto symbol = dynamic_cast<Symbol::FunctionSymbol*>(getManager()->getProgramModule()->getSymbolManager()->getSymbolById(func_symbol_id));
	auto signature = dynamic_cast<DataType::Signature*>(getManager()->getProgramModule()->getTypeManager()->getTypeById(signature_id));
	auto module = getManager()->getProgramModule()->getProcessModuleManager()->getProcessModuleById(module_id);

	auto function =
		new Function::Function(
			getManager(),
			symbol,
			module,
			AddressRangeList(),
			signature
		);

	if (symbol) {
		symbol->setFunction(function);
	}

	if (stack_mem_area_id) {
		auto stack_mem_area = getManager()->getProgramModule()->getMemoryAreaManager()->getSymbolTableById(stack_mem_area_id);
		if (stack_mem_area != nullptr) {
			function->setStackMemoryArea(stack_mem_area);
		}
	}

	if (body_mem_area_id) {
		auto body_mem_area = getManager()->getProgramModule()->getMemoryAreaManager()->getSymbolTableById(body_mem_area_id);
		if (body_mem_area != nullptr) {
			function->setBodyMemoryArea(body_mem_area);
		}
	}
	
	function->setId(func_id);
	function->setGhidraMapper(getManager()->m_ghidraFunctionMapper);
	return function;
}

void FunctionMapper::loadFunctionRanges(Database* db) {
	SQLite::Statement query(*db, "SELECT * FROM sda_func_ranges ORDER BY func_id, order_id");

	while (query.executeStep())
	{
		int func_id = query.getColumn("func_id");
		auto function = getManager()->getFunctionById(func_id);
		if (!function)
			continue;

		int min_offset = query.getColumn("min_offset");
		int max_offset = query.getColumn("max_offset");
		function->addRange(AddressRange(
			function->getProcessModule()->toAbsAddr(min_offset),
			function->getProcessModule()->toAbsAddr(max_offset)
		));
	}
}

void FunctionMapper::saveFunctionRanges(TransactionContext* ctx, CE::Function::Function& function) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_func_ranges WHERE func_id=?1");
		query.bind(1, function.getId());
		query.exec();
	}

	{
		int order_id = 0;
		for (auto& range : function.getAddressRangeList()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_func_ranges (func_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, function.getId());
			query.bind(2, order_id);
			query.bind(3, function.getProcessModule()->toRelAddr(range.getMinAddress()));
			query.bind(4, function.getProcessModule()->toRelAddr(range.getMaxAddress()));
			query.exec();
			order_id++;
		}
	}
}

void FunctionMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void FunctionMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto& def = *static_cast<CE::Function::Function*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_functions (func_id, func_symbol_id, signature_id, module_id, stack_mem_area_id, body_mem_area_id, exported, save_id)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
	query.bind(1, def.getId());
	bind(query, def);
	query.bind(8, ctx->m_saveId);
	query.exec();
	saveFunctionRanges(ctx, def);
}

void FunctionMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_functions SET deleted=1" : "DELETE FROM sda_functions";
	Statement query(*ctx->m_db, action_query_text + " WHERE func_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionMapper::bind(SQLite::Statement& query, CE::Function::Function& def) {
	query.bind(2, def.getFunctionSymbol()->getId());
	query.bind(3, def.getSignature()->getId());
	query.bind(4, def.getProcessModule()->getId());
	query.bind(5, def.getStackMemoryArea() ? def.getStackMemoryArea()->getId() : 0);
	query.bind(6, def.getBodyMemoryArea() ? def.getBodyMemoryArea()->getId() : 0);
	query.bind(7, def.isExported());
}
