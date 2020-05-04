#pragma once
#include "UserType.h"

namespace CE
{
	namespace DataType
	{
		class Typedef : public UserType
		{
		public:
			Typedef(TypeManager* typeManager, DataTypePtr refType, const std::string& name, const std::string& desc = "");

			Group getGroup() override;

			int getSize() override;

			std::string getViewValue(void* addr) override;

			void setRefType(DataTypePtr refType);

			DataTypePtr getRefType();
		private:
			DataTypePtr m_refType;
		};
	};
};