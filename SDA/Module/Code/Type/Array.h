#pragma once
#include "Pointer.h"

namespace CE
{
	namespace Type
	{
		//MYTODO: массив массивов(arr[2][5]) -> isArrayOfObjects линейный массив arr[10]. Доступ по формулу i*n+j   ИЛИ   isArrayOfPointers массив указателей(pLvl = 2, arrSize = 2 * 8 * 5 * 4) Решение: юзать через классы
		class Array : public Pointer
		{
		public:
			Array(Type* type, uint64_t arraySize)
				: Pointer(type), m_arraySize(arraySize)
			{}

			std::string getDisplayName() override;

			int getSize() override;

			//MYTODO: сделать getArrayInfo, где в битах хранить размерность
			int getArraySize() override;

			int getItemSize();
		private:
			uint64_t m_arraySize;
		};
	};
};