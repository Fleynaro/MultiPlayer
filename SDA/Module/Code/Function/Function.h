#pragma once
#include <GhidraSync/GhidraObject.h>
#include "../Type/FunctionSignature.h"
#include "../Symbol/Symbol.h"

namespace CE
{
	namespace Trigger::Function
	{
		class Hook;
	};

	namespace Decompiler
	{
		class FunctionPCodeGraph;
	};

	class FunctionManager;

	namespace Function
	{
		class Function : public DB::DomainObject, public Ghidra::Object, public IDescription
		{
		public:
			Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, Decompiler::FunctionPCodeGraph* funcGraph, Symbol::SymbolTable* stackSymbolTable)
				: m_manager(manager), m_functionSymbol(functionSymbol), m_funcGraph(funcGraph), m_stackSymbolTable(stackSymbolTable)
			{}

			Symbol::FunctionSymbol* getFunctionSymbol();

			Decompiler::FunctionPCodeGraph* getFuncGraph();

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			DataType::IFunctionSignature* getSignature();

			int getOffset();

			Symbol::SymbolTable* getStackSymbolTable();

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			Ghidra::Id getGhidraId() override;

			FunctionManager* getManager();
		private:
			Decompiler::FunctionPCodeGraph* m_funcGraph;
			Symbol::FunctionSymbol* m_functionSymbol;
			Symbol::SymbolTable* m_stackSymbolTable;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionManager* m_manager;
		};
	};
};