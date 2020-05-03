#pragma once
#include "Pointer.h"

namespace CE
{
	namespace DataType
	{
		//MYTODO: ������ ��������(arr[2][5]) -> isArrayOfObjects �������� ������ arr[10]. ������ �� ������� i*n+j   ���   isArrayOfPointers ������ ����������(pLvl = 2, arrSize = 2 * 8 * 5 * 4) �������: ����� ����� ������
		class Array : public Pointer
		{
		public:
			Array(TypeManager* typeManager, Type* type, uint64_t arraySize)
				: Pointer(typeManager, type), m_arraySize(arraySize)
			{}

			std::string getDisplayName() override;

			int getSize() override;

			//MYTODO: ������� getArrayInfo, ��� � ����� ������� �����������
			int getArraySize() override;

			int getItemSize();
		private:
			uint64_t m_arraySize;
		};
	};
};