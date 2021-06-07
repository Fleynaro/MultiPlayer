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
			virtual bool isAutoSymbol() = 0;

			virtual Type getType() = 0;

			virtual DataTypePtr getDataType() = 0;

			virtual void setDataType(DataTypePtr dataType) = 0;

			virtual int getSize() {
				return getDataType()->getSize();
			}
		};

		class AbstractSymbol : virtual public ISymbol, public DB::DomainObject, public Descrtiption
		{
		public:
			AbstractSymbol(DataTypePtr dataType, const std::string& name, const std::string& comment = "")
				: m_dataType(dataType), Descrtiption(name, comment)
			{}

			void setAutoSymbol(bool toggle);

			bool isAutoSymbol() override;

			SymbolManager* getManager();

			DataTypePtr getDataType() override;

			void setDataType(DataTypePtr dataType) override;
		private:
			DataTypePtr m_dataType;
			SymbolManager* m_manager;
			bool m_isAutoSymbol;
		};
	};
};