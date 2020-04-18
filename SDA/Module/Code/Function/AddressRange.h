#pragma once
#include "main.h"

namespace CE
{
	namespace Trigger::Function
	{
		class Hook;
	};

	namespace Function
	{
		class AddressRange
		{
		public:
			AddressRange() = default;
			AddressRange(void* min_addr, void* max_addr);
			AddressRange(void* entry_addr, int size);

			bool isContainingAddress(void* addr);

			std::uintptr_t getSize();

			void* getMinAddress();

			void* getMaxAddress();
		private:
			void* m_min_addr = nullptr;
			void* m_max_addr = nullptr;
		};

		using AddressRangeList = std::vector<AddressRange>;
	};
};