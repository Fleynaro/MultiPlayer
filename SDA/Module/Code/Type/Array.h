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

			std::string getDisplayName() override {
				return getType()->getDisplayName() + "[" + std::to_string(getArraySize()) + "]";
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

			int getItemSize() {
				return getType()->getSize();
			}
		private:
			uint64_t m_arraySize;
		};
	};
};