#include "BeforeCallInfo.h"

using namespace CE::Stat::Function::Record::BeforeCallInfo;

Reader::Reader(Buffer::Stream* bufferStream)
	: m_bufferStream(bufferStream)
{
	m_argHeader = getStream().readPtr<ArgHeader>();
}

Reader::ArgInfo Reader::readArgument() {
	ArgInfo argInfo;

	argInfo.m_value = getStream().read<uint64_t>();
	if (m_curArgIdx >= 1 && m_curArgIdx <= 4) {
		argInfo.m_xmmValue = getStream().read<uint64_t>();
		argInfo.m_hasXmmValue = true;
	}

	if (m_argHeader->m_argExtraBits >> (m_curArgIdx - 1) & 0b1) {
		argInfo.m_extraDataSize = getStream().read<USHORT>();
		argInfo.m_extraData = getStream().readPtr(argInfo.m_extraDataSize);
	}

	m_curArgIdx++;
	return argInfo;
}

ArgHeader& Reader::getArgHeader() {
	return *m_argHeader;
}

Buffer::Stream& Reader::getStream() {
	return m_bufferStream;
}




Writer::Writer(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
	: CallInfoWriter(trigger, hook)
{}

void Writer::write() {
	//write header
	writeHeader(Type::BeforeCallInfo);

	//write argument values
	ArgHeader argHeader;
	argHeader.m_argExtraBits = 0;
	argHeader.m_argCount = m_hook->getArgCount();
	m_argHeader = getStream().getNext<ArgHeader>();
	getStream().write(argHeader);

	for (int argIdx = 1; argIdx <= m_hook->getArgCount(); argIdx++) {
		writeArgument(argIdx);
	}
}

void Writer::writeArgument(int argIdx) {
	auto argValue = m_hook->getArgumentValue(argIdx);
	getStream().write(argValue);
	if (argIdx >= 1 && argIdx <= 4) {
		getStream().write(m_hook->getXmmArgumentValue(argIdx));
	}

	writeArgumentExtra(argIdx, (void*)argValue);
}

void Writer::writeArgumentExtra(int argIdx, void* argAddrValue) {
	/*
	Могут содержаться в регистре:
	1) Числа
	2) Указатели, массивы, объекты в стеке -> ссылка
	Итог: все представимя в виде числа 8 байтового
	Задача: 8 байт -> массив байт(нач. адрес и размер)
	*/
	auto& argTypes = getFunctionDef()->getDeclaration().getSignature().getArgList();
	if (argIdx > argTypes.size())
		return;
	if (writeTypeValue(getStream(), argAddrValue, argTypes[argIdx - 1])) {
		m_argHeader->m_argExtraBits |= uint64_t(0b1) << (argIdx - 1);
	}
}
