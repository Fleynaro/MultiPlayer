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
	class ProcessModule;

	namespace Function
	{
		class Function : public DB::DomainObject, public Ghidra::Object, public IDescription
		{
		public:
			Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, Decompiler::FunctionPCodeGraph* funcGraph)
				: m_manager(manager), m_functionSymbol(functionSymbol), m_funcGraph(funcGraph)
			{}

			Symbol::FunctionSymbol* getFunctionSymbol();

			Decompiler::FunctionPCodeGraph* getFuncGraph();

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			DataType::IFunctionSignature* getSignature();

			int getOffset();

			Symbol::SymbolTable* getStackMemoryArea();

			void setStackMemoryArea(Symbol::SymbolTable* stackMemoryArea);

			Symbol::SymbolTable* getBodyMemoryArea();

			void setBodyMemoryArea(Symbol::SymbolTable* bodyMemoryArea);

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			void setExported(bool toggle);

			bool isExported();

			Ghidra::Id getGhidraId() override;

			ProcessModule* getProcessModule();

			FunctionManager* getManager();
		private:
			ProcessModule* m_processModule;
			Decompiler::FunctionPCodeGraph* m_funcGraph;
			Symbol::FunctionSymbol* m_functionSymbol;
			Symbol::SymbolTable* m_stackSymbolTable = nullptr;
			Symbol::SymbolTable* m_bodyMemoryArea = nullptr;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionManager* m_manager;
			bool m_exported = false;
		};
	};
};