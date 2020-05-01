#pragma once
#include "AbstractManager.h"
#include <Code/Function/FunctionDefinition.h>
#include "FunctionDeclManager.h"
#include <Utils/Iterator.h>

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
		class Iterator : public IIterator<Function::Function*>
		{
		public:
			Iterator(FunctionManager* manager);

			bool hasNext() override;

			Function::Function* next() override;
		private:
			ItemMapType::iterator m_iterator;
			ItemMapType::iterator m_end;
		};

		FunctionManager(ProgramModule* module, FunctionDeclManager* funcDeclManager);

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
	};

	using FunctionDefManager = FunctionManager;
};