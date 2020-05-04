#pragma once
#include "../Variable/Variable.h"

namespace CE
{
	namespace Function
	{
		class Signature
		{
		public:
			using ArgTypeList = std::vector<DataTypePtr>;

			Signature() {}
			
			void setReturnType(DataTypePtr returnType);

			DataTypePtr getReturnType();

			ArgTypeList& getArgList();

			void addArgument(DataTypePtr type);

			void setArgument(int id, DataTypePtr type);

			void removeLastArgument();

			void deleteAllArguments();
		private:
			ArgTypeList m_args;
			DataTypePtr m_returnType;
		};
	};
};