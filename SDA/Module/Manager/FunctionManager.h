#pragma once
#include "AbstractManager.h"
#include <Code/Function/FunctionDefinition.h>

namespace DB {
	class FunctionDefMapper;
};

namespace CE::Ghidra {
	class FunctionDefMapper;
};

namespace CE
{
	class FunctionTagManager;

	class FunctionManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Function::Function>;
		Ghidra::FunctionDefMapper* m_ghidraFunctionDefMapper;

		FunctionManager(ProgramModule* module);

		~FunctionManager();

		void loadFunctions();

		void loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		Function::Function* createFunction(Symbol::FunctionSymbol* functionSymbol, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature);

		Function::Function* createFunction(const std::string& name, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature, const std::string& comment = "");

		void createDefaultFunction();

		Function::Function* getDefaultFunction();

		Function::Function* getFunctionById(DB::Id id);

		Function::Function* getFunctionByGhidraId(Ghidra::Id id);

		Function::Function* getFunctionAt(void* addr);

		void buildFunctionBodies();

		void buildFunctionBasicInfo();

		void setFunctionTagManager(FunctionTagManager* manager);

		FunctionTagManager* getFunctionTagManager();
	private:
		FunctionTagManager* m_tagManager;
		Function::Function* m_defFunction = nullptr;
		DB::FunctionDefMapper* m_funcDefMapper;
	};
};