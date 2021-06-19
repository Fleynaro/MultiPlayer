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
	class FunctionManager : public AbstractItemManager
	{
	public:
		class Factory : public AbstractFactory
		{
			FunctionManager* m_functionManager;
			Ghidra::FunctionMapper* m_ghidraFunctionMapper;
			DB::FunctionMapper* m_funcMapper;
		public:
			Factory(FunctionManager* functionManager, Ghidra::FunctionMapper* ghidraFunctionMapper, DB::FunctionMapper* funcMapper, bool generateId)
				: m_functionManager(functionManager), m_ghidraFunctionMapper(ghidraFunctionMapper), m_funcMapper(funcMapper), AbstractFactory(generateId)
			{}

			Function::Function* createFunction(Symbol::FunctionSymbol* functionSymbol, ImageDecorator* imageDec, Symbol::SymbolTable* stackSymbolTable);

			Function::Function* createFunction(Symbol::FunctionSymbol* functionSymbol, ImageDecorator* imageDec);

			Function::Function* createFunction(int64_t offset, DataTypePtr type, ImageDecorator* imageDec, const std::string& name, const std::string& comment = "");
		};

		using Iterator = AbstractIterator<Function::Function>;
		Ghidra::FunctionMapper* m_ghidraFunctionMapper;

		FunctionManager(Project* module);

		~FunctionManager();

		Factory getFactory(bool generateId);

		void loadFunctions();

		void loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket);

		Function::Function* findFunctionById(DB::Id id);

		Function::Function* findFunctionByGhidraId(Ghidra::Id id);
	private:
		DB::FunctionMapper* m_funcMapper;
	};
};