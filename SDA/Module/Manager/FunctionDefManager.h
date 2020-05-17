#pragma once
#include "AbstractManager.h"
#include <Code/Function/FunctionDefinition.h>
#include "FunctionDeclManager.h"
#include <Utils/Iterator.h>

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

		FunctionManager(ProgramModule* module, FunctionDeclManager* funcDeclManager);

		~FunctionManager();

		void loadFunctions();

		void loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		Function::Function* createFunction(ProcessModule* module, AddressRangeList ranges, CE::Function::FunctionDecl* decl);

		void createDefaultFunction();

		Function::Function* getDefaultFunction();

		Function::Function* getFunctionById(DB::Id id);

		Function::Function* getFunctionByGhidraId(Ghidra::Id id);

		Function::Function* getFunctionAt(void* addr);

		FunctionDeclManager* getFunctionDeclManager();

		void buildFunctionBodies();

		void buildFunctionBasicInfo();

		void setFunctionTagManager(FunctionTagManager* manager);

		FunctionTagManager* getFunctionTagManager();
	private:
		FunctionDeclManager* m_funcDeclManager;
		FunctionTagManager* m_tagManager;
		Function::Function* m_defFunction = nullptr;
		DB::FunctionDefMapper* m_funcDefMapper;
	};

	using FunctionDefManager = FunctionManager;
};