#include "GhidraFunctionDefMapper.h"
#include <Manager/FunctionDefManager.h>
#include <Manager/ProcessModuleManager.h>

using namespace CE;
using namespace CE::Ghidra;

FunctionDefMapper::FunctionDefMapper(CE::FunctionManager* functionManager)
	: m_functionManager(functionManager)
{}

void FunctionDefMapper::load(DataPacket * dataPacket) {
	for (auto funcDesc : dataPacket->m_functions) {
		auto function = m_functionManager->getFunctionByGhidraId(funcDesc.id);
		if (function == nullptr) {
			function = m_functionManager->createFunction(m_functionManager->getProgramModule()->getProcessModuleManager()->getMainModule(), {}, m_functionManager->getFunctionDeclManager()->createFunctionDecl("", ""));
		}
		changeFunctionByDesc(function, funcDesc);
	}
}

void markObjectAsSynced(SyncContext* ctx, Function::Function* func) {
	SQLite::Statement query(*ctx->m_db, "UPDATE sda_func_defs SET ghidra_sync_id=?1 WHERE def_id=?2");
	query.bind(1, ctx->m_syncId);
	query.bind(2, func->getId());
	query.exec();
}

void FunctionDefMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto func = static_cast<Function::Function*>(obj);
	ctx->m_dataPacket->m_functions.push_back(buildDesc(func));
	markObjectAsSynced(ctx, func);
}

void FunctionDefMapper::remove(SyncContext* ctx, IObject* obj) {
	auto func = static_cast<Function::Function*>(obj);
	ctx->m_dataPacket->m_functions.push_back(buildDescToRemove(func));
	markObjectAsSynced(ctx, func);
}

AddressRangeList FunctionDefMapper::getRangesFromDesc(const std::vector<function::SFunctionRange>& rangeDescs) {
	AddressRangeList ranges;
	for (auto& range : rangeDescs) {
		ranges.push_back(AddressRange(
			m_functionManager->getProgramModule()->getProcessModuleManager()->getMainModule()->toAbsAddr(range.minOffset),
			m_functionManager->getProgramModule()->getProcessModuleManager()->getMainModule()->toAbsAddr(range.maxOffset)
		));
	}
	return ranges;
}

void FunctionDefMapper::changeFunctionByDesc(Function::Function* function, const function::SFunction& funcDesc) {
	function->getDeclaration().setName(funcDesc.name);
	function->getDeclaration().setComment(funcDesc.comment);

	auto& signature = function->getSignature();
	/*signature.setReturnType(
	getClient()->m_dataTypeManager->getType(funcDesc.signature.returnType)
	);*/

	function->getDeclaration().deleteAllArguments();
	auto& args = funcDesc.signature.arguments;
	for (int i = 0; i < args.size(); i++) {
		/*function->getDeclaration().addArgument(getClient()->m_dataTypeManager->getType(args[i]), funcDesc.argumentNames[i]);*/
	}

	function->getAddressRangeList().clear();
	function->getAddressRangeList() = getRangesFromDesc(funcDesc.ranges);
}

function::SFunction FunctionDefMapper::buildDescToRemove(Function::Function* function) {
	function::SFunction funcDesc;
	funcDesc.__set_id(function->getGhidraId());
	funcDesc.__set_name("{remove}");
	return funcDesc;
}

function::SFunction FunctionDefMapper::buildDesc(Function::Function* function) {
	function::SFunction funcDesc;
	funcDesc.__set_id(function->getGhidraId());

	auto spliter = function->getName().find("::");
	if (spliter != std::string::npos) {
		std::string funcName = function->getName();
		funcName[spliter] = '_';
		funcName[spliter + 1] = '_';
		funcDesc.__set_name(funcName);
	}
	else {
		funcDesc.__set_name(function->getName());
	}

	funcDesc.__set_comment(function->getComment());

	auto& signature = function->getSignature();
	/*funcDesc.signature.__set_returnType(
	getClient()->m_dataTypeManager->getTypeUnit(signature.getReturnType())
	);*/
	for (int i = 0; i < signature.getArgList().size(); i++) {
		auto argType = signature.getArgList()[i];
		auto argName = function->getArgNameList()[i];
		/*funcDesc.signature.arguments.push_back(getClient()->m_dataTypeManager->getTypeUnit(argType));*/
		funcDesc.argumentNames.push_back(argName);
	}

	for (auto& range : function->getAddressRangeList()) {
		function::SFunctionRange rangeDesc;
		rangeDesc.__set_minOffset(m_functionManager->getProgramModule()->getProcessModuleManager()->getMainModule()->toRelAddr(range.getMinAddress()));
		rangeDesc.__set_maxOffset(m_functionManager->getProgramModule()->getProcessModuleManager()->getMainModule()->toRelAddr(range.getMaxAddress()));
		funcDesc.ranges.push_back(rangeDesc);
	}

	return funcDesc;
}
