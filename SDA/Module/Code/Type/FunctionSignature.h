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

			std::string getDisplayName() override;

			CallingConvetion getCallingConvetion();

			std::list<std::pair<int, Decompiler::Storage>>& getCustomStorages();

			std::string getSigName();

			void setReturnType(DataTypePtr returnType);

			DataTypePtr getReturnType();

			std::vector<Symbol::FuncParameterSymbol*>& getParameters();

			void addParameter(Symbol::FuncParameterSymbol* symbol);

			void addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment = "");

			void removeLastParameter();

			void deleteAllParameters();

			Decompiler::FunctionCallInfo getCallInfo();

		private:
			CallingConvetion m_callingConvetion;
			std::list<Decompiler::ParameterInfo> m_paramInfos;
			bool m_hasSignatureUpdated = false;
			std::list<std::pair<int, Decompiler::Storage>> m_customStorages;
			std::vector<Symbol::FuncParameterSymbol*> m_parameters;
			DataTypePtr m_returnType;

			void updateParameterStorages();
		};
	};
};