#include "FunctionTriggerTableLog.h"

using namespace CE::Trigger;
using namespace CE::Trigger::Function;

//SeqAllocator
SeqAllocator::SeqAllocator(int size)
	: m_size(size)
{}

SeqAllocator::~SeqAllocator() {
	clear();
}

Buffer::Stream& SeqAllocator::getStream() {
	if (m_curBuffer == nullptr) {
		createNewBuffer();
	}
	return m_bufferStream;
}

bool SeqAllocator::isFilled() {
	auto isFilled = m_curBuffer->getFreeSpaceSize() == 0;
	if (isFilled) {
		createNewBuffer();
	}
	return isFilled;
}

void SeqAllocator::clear() {
	for (auto it : m_buffers) {
		Buffer::Destroy(it);
	}
	m_buffers.clear();
	m_curBuffer = nullptr;
}

void SeqAllocator::createNewBuffer() {
	m_buffers.push_back(m_curBuffer = Buffer::Create(m_size));
	m_bufferStream = Buffer::Stream(m_curBuffer);
	m_size *= 2;
}

//Value
Value::Value(CE::DataTypePtr type, uint64_t rawValue, void* rawData)
	: m_type(type), m_rawValue(rawValue), m_rawData(rawData)
{
	if (m_rawData != nullptr) {
		//mytodo: так можно?
		m_type = CE::DataType::GetUnit(m_type->getType(), "*");
	}
}

bool Value::isString() const {
	return m_rawData != nullptr && m_type->isString();
}

void* Value::getRawData() const {
	if (m_rawData == nullptr)
		return nullptr;
	return (void*)((std::uintptr_t)m_rawData + sizeof(USHORT) + sizeof(BYTE));
}

USHORT Value::getRawDataSize() {
	return *(USHORT*)((std::uintptr_t)m_rawData + sizeof(BYTE));
}

//TimeData
TimeData::TimeData()
{
	m_startTime = Clock::now();
}

void TimeData::setEndTime() {
	m_endTime = Clock::now();
}

float TimeData::getElapsedTime() const {
	auto ns = m_endTime - m_startTime;
	return (float)ns.count() / 1000.0f;
}

//StatData
StatData::StatData(bool filterBefore)
	: m_filterBefore(filterBefore)
{}


//TableLog
TableLog::TableLog(Function::Trigger* trigger)
	: m_trigger(trigger), m_allocator(1024 * 128)
{}

void TableLog::addBeforeCallRow(CE::Hook::DynHook* hook, bool filter)
{
	if (!m_enabled)
		return;
	if (size() > 10000)
		return;

	auto funcDef = (CE::Function::FunctionDefinition*)hook->getUserPtr();

	m_mutex.lock();
	addRow(
		hook->getUID(),
		funcDef->getId(),
		TimeData(),
		getArgValues(funcDef, hook),
		Value(),
		nullptr,
		StatData(filter)
	);
	m_mutex.unlock();
}

void TableLog::addAfterCallRow(CE::Hook::DynHook* hook, bool filter)
{
	if (!m_enabled)
		return;

	auto row = getRow(hook->getUID());
	if (row == nullptr)
		return;
	auto funcDef = (CE::Function::FunctionDefinition*)hook->getUserPtr();
	m_mutex.lock();
	std::get<RetValue>(*row) = getRetValue(funcDef, hook);
	m_mutex.unlock();
	std::get<Time>(*row).setEndTime();
	std::get<RetAddr>(*row) = hook->getReturnAddress();
	std::get<Stat>(*row).m_filterAfter = filter;
}

std::list<Value> TableLog::getArgValues(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
	std::list<Value> values;
	auto& argTypes = funcDef->getDeclaration().getSignature()->getParameters();
	for (int argIdx = 1; argIdx <= min(hook->getArgCount(), argTypes.size()); argIdx++) {
		auto type = argTypes[argIdx - 1]->getDataType();
		void* rawData = nullptr;

		if (type->isPointer()) {
			getExtraValue((void*)hook->getArgumentValue(argIdx), type, rawData);
		}

		values.push_back(
			Value(
				type,
				Function::GetArgumentValue(type, hook, argIdx),
				rawData
			)
		);
	}
	return values;
}

Value TableLog::getRetValue(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
	auto retType = funcDef->getDeclaration().getSignature()->getReturnType();
	void* rawData = nullptr;

	if (retType->isPointer()) {
		getExtraValue((void*)hook->getReturnValue(), retType, rawData);
	}

	return Value(
		retType,
		Function::GetReturnValue(retType, hook),
		rawData
	);
}

void TableLog::getExtraValue(void* addrValue, CE::DataTypePtr argType, void*& dest) {
	do {
		dest = m_allocator.getStream().getNext();
		if (!Stat::Function::Record::CallInfoWriter::writeTypeValue(m_allocator.getStream(), addrValue, argType)) {
			dest = nullptr;
		}
	} while (m_allocator.isFilled());
}

void TableLog::onClear() {
	m_allocator.clear();
}