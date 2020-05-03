#pragma once
#include "UserType.h"

namespace CE
{
	namespace DataType
	{
		class Typedef : public UserType
		{
		public:
			Typedef(Type* refType, const std::string& name, const std::string& desc = "");

			Group getGroup() override;

			int getSize() override;

			std::string getViewValue(void* addr) override;

			int getPointerLvl() override;

			int getArraySize() override;

			void setRefType(Type* refType);

			Type* getRefType();
		private:
			Type* m_refType = nullptr;
		};
	};
};