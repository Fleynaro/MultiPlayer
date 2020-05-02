#pragma once
#include "../Variable/Variable.h"

namespace CE
{
	namespace Function
	{
		class Signature
		{
		public:
			using ArgTypeList = std::vector<DataType::Type*>;

			Signature() {}
			~Signature();

			void setReturnType(DataType::Type* returnType);

			DataType::Type* getReturnType();

			ArgTypeList& getArgList();

			void addArgument(DataType::Type* type);

			void changeArgument(int id, DataType::Type* type);

			void removeLastArgument();

			void deleteAllArguments();
		private:
			ArgTypeList m_args;
			DataType::Type* m_returnType = nullptr;
		};
	};
};