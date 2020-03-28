#pragma once
#include "Pointer.h"

namespace CE
{
	namespace Type
	{
		//MYTODO: ������ ��������(arr[2][5]) -> isArrayOfObjects �������� ������ arr[10]. ������ �� ������� i*n+j   ���   isArrayOfPointers ������ ����������(pLvl = 2, arrSize = 2 * 8 * 5 * 4) �������: ����� ����� ������
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

			//MYTODO: ������� getArrayInfo, ��� � ����� ������� �����������
			int getArraySize() override {
				return static_cast<int>(m_arraySize);
			}

			int getItemSize() {
				return getType()->getSize();
			}
		private:
			uint64_t m_arraySize;
		};
	};
};