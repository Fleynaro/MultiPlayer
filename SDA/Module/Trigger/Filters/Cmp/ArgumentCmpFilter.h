#pragma once
#include "../AbstractFilter.h"
#include "CmpFilterHelper.h"

namespace CE::Trigger::Function::Filter::Cmp
{
	class Argument : public AbstractFilter
	{
	public:

		Argument() = default;
		Argument(int argId, uint64_t value, Operation operation)
			: m_argId(argId), m_value(value), m_operation(operation)
		{}

		Id getId() override {
			return Id::Argument;
		}

		bool checkFilterBefore(CE::Hook::DynHook* hook) override {
			using namespace CE::DataType;

			auto function = (CE::Function::FunctionDefinition*)hook->getUserPtr();
			auto& argList = function->getDeclaration().getSignature().getArgList();
			if (m_argId > argList.size())
				return false;

			auto type = argList[m_argId - 1];
			return cmp(
				GetArgumentValue(type, hook, m_argId),
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
			data.m_argId = m_argId;
			data.m_value = m_value;
			data.m_operation = m_operation;
			bt.write(&data, sizeof(Data));
		}

		void deserialize(BitStream& bt)
		{
			Data data;
			bt.read(&data, sizeof(Data));
			m_argId = data.m_argId;
			m_value = data.m_value;
			m_operation = data.m_operation;
		}

		int m_argId = 1;
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