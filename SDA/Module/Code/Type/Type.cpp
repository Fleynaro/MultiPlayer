#include "Type.h"

CE::Type::SystemType::Types CE::Type::SystemType::GetBasicTypeOf(Type* type)
{
	if (type != nullptr)
	{
		if (type->isSystem())
			return static_cast<Types>(type->getId());
		if (type->getGroup() == Typedef)
			return GetBasicTypeOf(static_cast<CE::Type::Typedef*>(type)->getRefType());
	}
	return Types::Void;
}

CE::Type::SystemType::Set CE::Type::SystemType::GetNumberSetOf(Type* type)
{
	if (type->isSystem() && !type->isPointer() && !type->isArray())
		return static_cast<SystemType*>(type)->getSet();
	if (type->getGroup() == Typedef)
		return GetNumberSetOf(static_cast<CE::Type::Typedef*>(type)->getRefType());
	return Set::Undefined;
}