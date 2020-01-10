#pragma once
#include "UserType.h"

namespace CE
{
	namespace Type
	{
		class Typedef : public UserType
		{
		public:
			Typedef(Type* refType, int id, std::string name, std::string desc = "")
				: UserType(id, name, desc)
			{
				setRefType(refType);
			}

			Group getGroup() override {
				return Group::Typedef;
			}

			int getSize() override {
				if (getRefType() == this)
					return 0;
				return getRefType()->getSize();
			}

			void setRefType(Type* refType) {
				m_refType = refType;
			}

			Type* getRefType() {
				return m_refType;
			}
		private:
			Type* m_refType = nullptr;
		};
	};
};