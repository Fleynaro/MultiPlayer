#pragma once
#include "AbstractType.h"

namespace CE
{
	namespace Type
	{
		class Pointer : public Type
		{
		public:
			Pointer(Type* type)
				: m_type(type)
			{}

			void free() override {
				getType()->free();
				delete this;
			}

			Group getGroup() override {
				return getType()->getGroup();
			}

			bool isUserDefined() override {
				return getType()->isUserDefined();
			}

			int getId() override {
				return getType()->getId();
			}

			std::string getName() override {
				return getType()->getName();
			}

			std::string getDisplayName() override {
				return getType()->getName() + "*";
			}

			int getSize() override {
				return 8;
			}

			Type* getType() {
				return m_type;
			}

			int getPointerLvl() override {
				return getType()->getPointerLvl() + 1;
			}

			int getArraySize() override {
				return 0;
			}
		private:
			Type* m_type;
		};
	};
};