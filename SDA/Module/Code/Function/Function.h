#pragma once
#include <GhidraSync/GhidraObject.h>
#include "../Type/FunctionSignature.h"
#include "../Symbol/Symbol.h"
#include <Image/ImageDecorator.h>

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
			Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, ImageDecorator* imageDec, Symbol::SymbolTable* stackSymbolTable)
				: m_manager(manager), m_functionSymbol(functionSymbol), m_imageDec(imageDec), m_stackSymbolTable(stackSymbolTable)
			{
				functionSymbol->setFunction(this);
			}

			Symbol::FunctionSymbol* getFunctionSymbol();

			ImageDecorator* getImage();

			Decompiler::FunctionPCodeGraph* getFuncGraph();

			const std::string getName() override;

			const std::string getComment() override;

			void setName(const std::string& name) override;

			void setComment(const std::string& comment) override;

			DataType::IFunctionSignature* getSignature();

			int64_t getOffset();

			Symbol::SymbolTable* getStackSymbolTable();

			Trigger::Function::Hook* getHook();

			bool hasHook();

			void createHook();

			Ghidra::Id getGhidraId() override;

			FunctionManager* getManager();
		private:
			ImageDecorator* m_imageDec;
			Symbol::FunctionSymbol* m_functionSymbol;
			Symbol::SymbolTable* m_stackSymbolTable;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionManager* m_manager;
		};
	};
};