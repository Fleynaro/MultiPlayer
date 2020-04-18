#pragma once
#include <Code/Code.h>

namespace CE::Trigger::Function::Filter::Cmp
{
	enum Operation
	{
		Eq,
		Neq,
		Lt,
		Le,
		Gt,
		Ge
	};

	template<typename T>
	static bool cmp(T op1, T op2, Operation operation)
	{
		switch (operation)
		{
		case Operation::Eq: return op1 == op2;
		case Operation::Neq: return op1 != op2;
		case Operation::Lt: return op1 < op2;
		case Operation::Le: return op1 <= op2;
		case Operation::Gt: return op1 > op2;
		case Operation::Ge: return op1 >= op2;
		}
		return false;
	}

	static bool cmp(uint64_t op1, uint64_t op2, Operation operation, CE::Type::Type* type)
	{
		using namespace CE::Type;
		if (!type->isPointer()) {
			switch (type->getBaseType()->getId())
			{
			case SystemType::Bool:
			case SystemType::Byte:
				return cmp(static_cast<BYTE>(op1), static_cast<BYTE>(op2), operation);
			case SystemType::Int8:
				return cmp(static_cast<int8_t>(op1), static_cast<int8_t>(op2), operation);
			case SystemType::Int16:
				return cmp(static_cast<int16_t>(op1), static_cast<int16_t>(op2), operation);
			case SystemType::Int32:
				return cmp(static_cast<int32_t>(op1), static_cast<int32_t>(op2), operation);
			case SystemType::Int64:
				return cmp(static_cast<int64_t>(op1), static_cast<int64_t>(op2), operation);
			case SystemType::UInt16:
			case SystemType::UInt32:
			case SystemType::UInt64:
				return cmp(static_cast<uint64_t>(op1), static_cast<uint64_t>(op2), operation);
			case SystemType::Float:
				return cmp(reinterpret_cast<float&>(op1), reinterpret_cast<float&>(op2), operation);
			case SystemType::Double:
				return cmp(reinterpret_cast<double&>(op1), reinterpret_cast<double&>(op2), operation);
			}
		}
		return cmp(static_cast<uint64_t>(op1), static_cast<uint64_t>(op2), operation);
	}
};