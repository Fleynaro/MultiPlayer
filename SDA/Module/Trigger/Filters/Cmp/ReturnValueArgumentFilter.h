#pragma once
#include "../AbstractFilter.h"
#include "CmpFilterHelper.h"

namespace CE::Trigger::Function::Filter::Cmp
{
	class RetValue : public AbstractFilter
	{
	public:
		RetValue() = default;
		RetValue(uint64_t value, Operation operation)
			: m_value(value), m_operation(operation)
		{}

		Id getId() override {
			return Id::ReturnValue;
		}

		bool checkFilterAfter(CE::Hook::DynHook* hook) override {
			using namespace CE::DataType;

			auto function = (CE::Function::Function*)hook->getUserPtr();
			auto type = function->getSignature().getReturnType();
			return cmp(
				GetReturnValue(type, hook),
				m_value,
				m_operation,
				type
			);
		}

		template<typename T = uint64_t>
		void setValue(T value) {
			(T&)m_value = value;
		}

		void setOperation(Operation operation) {
			m_operation = operation;
		}

		void serialize(BitStream& bt)
		{
			Data data;
			data.m_value = m_value;
			data.m_operation = m_operation;
			bt.write(&data, sizeof(Data));
		}

		void deserialize(BitStream& bt)
		{
			Data data;
			bt.read(&data, sizeof(Data));
			m_value = data.m_value;
			m_operation = data.m_operation;
		}

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