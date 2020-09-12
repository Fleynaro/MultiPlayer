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

		class ISymbol : virtual public IDescription
		{
		public:
			virtual Type getType() = 0;

			virtual DataTypePtr getDataType() = 0;

			virtual void setDataType(DataTypePtr dataType) = 0;
		};

		class AbstractSymbol : virtual public ISymbol, public DB::DomainObject, public Descrtiption
		{
		public:
			AbstractSymbol(SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "");

			SymbolManager* getManager();

			DataTypePtr getDataType() override;

			void setDataType(DataTypePtr dataType) override;
		private:
			DataTypePtr m_dataType;
			SymbolManager* m_manager;
		};
	};
};