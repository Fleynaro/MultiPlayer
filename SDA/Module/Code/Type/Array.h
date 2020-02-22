#pragma once
#include "Pointer.h"

namespace CE
{
	namespace Type
	{
		class Array : public Pointer
		{
		public:
			Array(Type* type, uint64_t arraySize)
				: Pointer(type), m_arraySize(arraySize)
			{}

			Group getGroup() override {
				return getType()->getGroup();
			}

			std::string getName() override {
				return getType()->getName();
			}

			std::string getDesc() override {
				return getType()->getDesc();
			}

			std::string getDisplayName() override {
				return getType()->getName() + "[" + std::to_string(getArraySize()) + "]";
			}

			int getSize() override {
				return getArraySize() * getType()->getSize();
			}

			int getPointerLvl() override {
				return getType()->getPointerLvl();
			}

			int getArraySize() override {
				return m_arraySize;
			}
		private:
			uint64_t m_arraySize;
		};
	};
};