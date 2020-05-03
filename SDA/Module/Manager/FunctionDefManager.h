#pragma once
#include "AbstractManager.h"
#include <Code/Function/FunctionDefinition.h>
#include "FunctionDeclManager.h"
#include <Utils/Iterator.h>

namespace DB {
	class FunctionDefMapper;
};

namespace CE
{
	namespace Ghidra
	{
		class FunctionManager;
	};

	namespace Function::Tag
	{
		class Manager;
	};

	class FunctionManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Function::Function>;

		FunctionManager(ProgramModule* module, FunctionDeclManager* funcDeclManager);

		~FunctionManager();

		void loadFunctions();

		Function::Function* createFunction(void* addr, Function::AddressRangeList ranges, CE::Function::FunctionDecl* decl);

		void createDefaultFunction();

		Function::Function* getDefaultFunction();

		Function::Function* getFunctionById(DB::Id id);

		Function::Function* getFunctionAt(void* addr);

		FunctionDeclManager* getFunctionDeclManager();

		void buildFunctionBodies();

		void buildFunctionBasicInfo();

		void setFunctionTagManager(Function::Tag::Manager* manager);

		Function::Tag::Manager* getFunctionTagManager();

		void setGhidraManager(Ghidra::FunctionManager* ghidraManager);

		Ghidra::FunctionManager* getGhidraManager();

		bool isGhidraManagerWorking();
	private:
		FunctionDeclManager* m_funcDeclManager;
		Ghidra::FunctionManager* m_ghidraManager;
		Function::Function* m_defFunction = nullptr;
		Function::Tag::Manager* m_tagManager;
		DB::FunctionDefMapper* m_funcDefMapper;
	};

	using FunctionDefManager = FunctionManager;
};