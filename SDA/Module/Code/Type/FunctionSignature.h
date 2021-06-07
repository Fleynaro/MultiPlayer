#pragma once
#include "UserType.h"
#include "../Symbol/FuncParameterSymbol.h"
#include <Decompiler/DecStorage.h>

namespace CE
{
	namespace DataType
	{
		class ISignature
		{
		public:
			enum CallingConvetion {
				FASTCALL
			};

			virtual CallingConvetion getCallingConvetion() = 0;

			virtual std::list<std::pair<int, Decompiler::Storage>>& getCustomStorages() = 0;

			virtual std::string getSigName() = 0;

			virtual void setReturnType(DataTypePtr returnType) = 0;

			virtual DataTypePtr getReturnType() = 0;

			virtual std::vector<Symbol::FuncParameterSymbol*>& getParameters() = 0;

			virtual void addParameter(Symbol::FuncParameterSymbol* symbol) = 0;

			virtual void addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment = "") = 0;

			virtual void removeLastParameter() = 0;

			virtual void deleteAllParameters() = 0;

			virtual Decompiler::FunctionCallInfo getCallInfo() = 0;
		};

		class Signature : public UserType, public ISignature
		{
		public:
			Signature(const std::string& name, const std::string& comment = "", CallingConvetion callingConvetion = FASTCALL);
			
			Group getGroup() override;

			int getSize() override;

			std::string getDisplayName() override;

			CallingConvetion getCallingConvetion() override;

			std::list<std::pair<int, Decompiler::Storage>>& getCustomStorages() override;

			std::string getSigName() override;

			void setReturnType(DataTypePtr returnType) override;

			DataTypePtr getReturnType() override;

			std::vector<Symbol::FuncParameterSymbol*>& getParameters() override;

			void addParameter(Symbol::FuncParameterSymbol* symbol) override;

			void addParameter(const std::string& name, DataTypePtr dataType, const std::string& comment = "") override;

			void removeLastParameter() override;

			void deleteAllParameters() override;

			Decompiler::FunctionCallInfo getCallInfo() override;

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