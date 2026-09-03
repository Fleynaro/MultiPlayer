#pragma once
#include "AbstractManager.h"
#include <Code/Function/Function.h>

namespace DB {
	class FunctionMapper;
};

namespace CE::Ghidra {
	class FunctionMapper;
};

namespace CE
{
	class FunctionTagManager;

	class FunctionManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Function::Function>;
		Ghidra::FunctionMapper* m_ghidraFunctionMapper;

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

		void setFunctionTagManager(FunctionTagManager* manager);

		FunctionTagManager* getFunctionTagManager();
	private:
		FunctionTagManager* m_tagManager;
		Function::Function* m_defFunction = nullptr;
		DB::FunctionMapper* m_funcDefMapper;
	};
};