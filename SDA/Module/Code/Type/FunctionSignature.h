#pragma once
#include "UserType.h"

namespace CE
{
	namespace DataType
	{
		class Signature : public UserType
		{
		public:
			using ArgList = std::vector<std::pair<std::string, DataTypePtr>>;

			Signature(TypeManager* typeManager, const std::string& name, const std::string& comment = "");
			
			Group getGroup() override;

			int getSize() override;

			std::string getSigName();

			void setReturnType(DataTypePtr returnType);

			DataTypePtr getReturnType();

			ArgList& getArgList();

			void addArgument(const std::string& name, DataTypePtr type);

			void setArgumentName(int idx, const std::string& name);

			void setArgumentType(int idx, DataTypePtr type);

			void removeLastArgument();

			void deleteAllArguments();
		private:
			ArgList m_args;
			DataTypePtr m_returnType;
		};
	};
};