#pragma once
#include "AbstractFilter.h"

namespace CE::Trigger::Function::Filter
{
	class Empty : public AbstractFilter
	{
	public:
		Empty() {}

		Id getId() override;

		bool checkFilterBefore(CE::Hook::DynHook* hook) override;

		bool checkFilterAfter(CE::Hook::DynHook* hook) override;
	};

	class Object : public AbstractFilter
	{
	public:
		Object() = default;

		Object(void* addr);

		Id getId() override;

		bool checkFilterBefore(CE::Hook::DynHook* hook) override;

		void serialize(BitStream& bt) override;

		void deserialize(BitStream& bt) override;

		void* m_addr = nullptr;
	private:
		struct Data
		{
			void* m_addr;
		};				
	};
};