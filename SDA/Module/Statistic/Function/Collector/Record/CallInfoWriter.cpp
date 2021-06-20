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
	DereferenceIterator it(argAddrValue, argType);
	if(!it.hasNext())
		return false;
	auto firstItem = it.next();
	void* pObject = firstItem.first;
	int objSize = firstItem.second->getSize();
	bool isString = false;

	//Block 2: calculate size of the object if it is string
	if (argType->isString()) {
		char* str = (char*)pObject;
		objSize = 0;
		while (objSize < 100 && str[objSize] != '\0')
			objSize++;
		isString = true;
	}

	if (objSize == 0)
		return false;

	BYTE typeShortInfo = argType->getBaseType()->getGroup() & 0xF | ((byte)isString << 4);
	bufferStream.write(typeShortInfo);
	bufferStream.write((USHORT)objSize);
	bufferStream.writeFrom(pObject, objSize);
	return true;
}

CE::Function* Record::CallInfoWriter::getFunctionDef() {
	return (CE::Function*)m_hook->getUserPtr();
}