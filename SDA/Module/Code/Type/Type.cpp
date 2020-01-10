#include "Type.h"

CE::Type::SystemType::Types CE::Type::SystemType::GetBasicTypeOf(Type* type)
{
	if (type != nullptr)
	{
		if (type->isSystem())
			return (Types)type->getId();
		if (type->getGroup() == Typedef)
			return GetBasicTypeOf(((CE::Type::Typedef*)type)->getRefType());
	}
	return Types::Void;
}

CE::Type::SystemType::Set CE::Type::SystemType::GetNumberSetOf(Type* type)
{
	if (type->isSystem() && !type->isPointer() && !type->isArray())
		return ((SystemType*)type)->getSet();
	if (type->getGroup() == Typedef)
		return GetNumberSetOf(((CE::Type::Typedef*)type)->getRefType());
	return Set::Undefined;
}