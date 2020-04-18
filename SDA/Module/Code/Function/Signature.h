#pragma once
#include "../Variable/Variable.h"

namespace CE
{
	namespace Function
	{
		class Signature
		{
		public:
			using ArgTypeList = std::vector<Type::Type*>;

			Signature() {}
			~Signature();

			void setReturnType(Type::Type* returnType);

			Type::Type* getReturnType();

			ArgTypeList& getArgList();

			void addArgument(Type::Type* type);

			void changeArgument(int id, Type::Type* type);

			void removeLastArgument();

			void deleteAllArguments();
		private:
			ArgTypeList m_args;
			Type::Type* m_returnType = nullptr;
		};
	};
};