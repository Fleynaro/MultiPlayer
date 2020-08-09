#pragma once
#include "../Type/TypeUnit.h"

namespace CE
{
	class SymbolManager;

	namespace Symbol
	{
		class AbstractSymbol : public DB::DomainObject, public Descrtiption
		{
		public:
			enum Type {
				FUNCTION = 1,
				GLOBAL_VAR,
				LOCAL_VAR,
				LOCAL_STACK_VAR,
				FUNC_PARAMETER
			};

			AbstractSymbol(SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
				: m_manager(manager), m_dataType(dataType), Descrtiption(name, comment)
			{}

			SymbolManager* getManager() {
				return m_manager;
			}

			virtual Type getType() = 0;

			DataTypePtr getDataType() {
				return m_dataType;
			}

			void setDataType(DataTypePtr dataType) {
				m_dataType = dataType;
			}
		private:
			DataTypePtr m_dataType;
			SymbolManager* m_manager;
		};
	};
};