#pragma once
#include "../AbstractFilter.h"
#include "CmpFilterHelper.h"

namespace CE::Trigger::Function::Filter::Cmp
{
	class RetValue : public AbstractFilter
	{
	public:
		RetValue() = default;

		RetValue(uint64_t value, Operation operation);

		Id getId() override;

		bool checkFilterAfter(CE::Hook::DynHook* hook) override;

		template<typename T = uint64_t>
		void setValue(T value) {
			(T&)m_value = value;
		}

		void setOperation(Operation operation);

		void serialize(BitStream& bt) override;

		void deserialize(BitStream& bt) override;

		uint64_t m_value = 0;
		Operation m_operation = Operation::Eq;
	private:
		struct Data
		{
			int m_argId;
			uint64_t m_value;
			Operation m_operation;
		};
	};
};