#pragma once
#include "UserType.h"

namespace CE
{
	namespace DataType
	{
		class Typedef : public UserDefinedType
		{
		public:
			Typedef(TypeManager* typeManager, const std::string& name, const std::string& comment = "")
				: UserDefinedType(typeManager, name, comment)
			{
				m_refType = GetUnit(typeManager->getFactory().getDefaultType());
			}

			Group getGroup() override;

			int getSize() override;

			std::string getViewValue(uint64_t value) override;

			void setRefType(DataTypePtr refType);

			DataTypePtr getRefType();
		private:
			DataTypePtr m_refType;
		};
	};
};