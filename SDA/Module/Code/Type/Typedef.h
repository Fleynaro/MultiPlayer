#pragma once
#include "UserType.h"

namespace CE
{
	namespace DataType
	{
		class Typedef : public UserType
		{
		public:
			Typedef(TypeManager* typeManager, const std::string& name, const std::string& comment = "");

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