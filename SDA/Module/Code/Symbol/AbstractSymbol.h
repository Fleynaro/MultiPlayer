#pragma once
#include "../Type/TypeUnit.h"

namespace CE
{
	class SymbolManager;

	namespace Symbol
	{
		enum Type {
			FUNCTION = 1,
			GLOBAL_VAR,
			LOCAL_INSTR_VAR,
			LOCAL_STACK_VAR,
			FUNC_PARAMETER
		};

		class AbstractSymbol : public DB::DomainObject, public Descrtiption
		{
		public:
			AbstractSymbol(SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "");

			SymbolManager* getManager();

			virtual Type getType() = 0;

			DataTypePtr getDataType();

			void setDataType(DataTypePtr dataType);
		private:
			DataTypePtr m_dataType;
			SymbolManager* m_manager;
		};
	};
};