#pragma once
#include "UserType.h"
#include "../Symbol/FuncParameterSymbol.h"
#include <Decompiler/DecStorage.h>

namespace CE
{
	namespace DataType
	{
		class Signature : public UserType
		{
		public:
			enum CallingConvetion {
				FASTCALL
			};

			Signature(TypeManager* typeManager, const std::string& name, const std::string& comment = "", CallingConvetion callingConvetion = FASTCALL);
			
			Group getGroup() override;

			int getSize() override;

			std::string getDisplayName() override {
				return getSigName();
			}

			CallingConvetion getCallingConvetion() {
				return m_callingConvetion;
			}

			std::list<Decompiler::ParameterStorage>& getCustomStorages() {
				return m_customStorages;
			}

			std::string getSigName();

			void setReturnType(DataTypePtr returnType);

			DataTypePtr getReturnType();

			std::vector<Symbol::FuncParameterSymbol*>& getParameters();

			void addParameter(Symbol::FuncParameterSymbol* symbol);

			void addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment = "");

			void removeLastParameter();

			void deleteAllParameters();

		private:
			CallingConvetion m_callingConvetion;
			std::list<Decompiler::ParameterStorage> m_customStorages;
			std::vector<Symbol::FuncParameterSymbol*> m_parameters;
			DataTypePtr m_returnType;
		};
	};
};