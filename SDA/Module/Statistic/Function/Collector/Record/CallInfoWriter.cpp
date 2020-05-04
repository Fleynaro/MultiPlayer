#include "CallInfoWriter.h"
#include <Trigger/FunctionTrigger.h>

using namespace CE::Stat::Function;

void Record::CallInfoWriter::writeHeader(Type type) {
	Header header;
	header.m_type = (BYTE)type;
	header.m_uid = m_hook->getUID();
	header.m_triggerId = m_trigger->getId();
	header.m_funcDefId = getFunctionDef()->getId();
	getStream().write(header);
}

bool Record::CallInfoWriter::writeTypeValue(Buffer::Stream& bufferStream, void* argAddrValue, CE::DataTypePtr argType) {
	//MYTODO: 1) массив указателей 2) массив чисел 3) указатель на указатель 4) указатель 5) не указатель(в стеке)
	//MYTODO: узнать тип указателя: на стек, на кучу, массив ли?

	//Block 1: point to the begining of the object
	if (argType->getPointerLvl() > 1) {
		argAddrValue = Address::Dereference(argAddrValue, argType->getPointerLvl() - 1);
		if (argAddrValue == nullptr)
			return false;
	}

	if (!Address(argAddrValue).canBeRead())
		return false;

	//Block 2: calculate size of the object
	int size;
	if (true /*argType->isArrayOfObjects()*/) {
		size = argType->getSize();
	}
	else if (argType->isString()) {
		char* str = (char*)argAddrValue;
		size = 0;
		while (size < 100 && str[size] != '\0')
			size++;
	}
	else {
		size = argType->getBaseType()->getSize();
	}

	if (size == 0)
		return false;

	bufferStream.write((USHORT)size);
	bufferStream.writeFrom(argAddrValue, size);
	return true;
}

CE::Function::FunctionDefinition* Record::CallInfoWriter::getFunctionDef() {
	return (CE::Function::FunctionDefinition*)m_hook->getUserPtr();
}