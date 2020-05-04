#pragma once
#include "FunctionTrigger.h"
#include "Utils/Table.h"
#include <chrono>

//MYTODO: addOwner и прочее можно юзать только дл€ new аллокатора. ¬ыход - умные указатели

namespace CE::Trigger::Function
{
	class SeqAllocator
	{
	public:
		SeqAllocator(int size)
			: m_size(size)
		{}

		~SeqAllocator() {
			clear();
		}

		Buffer::Stream& getStream() {
			if (m_curBuffer == nullptr) {
				createNewBuffer();
			}
			return m_bufferStream;
		}

		bool isFilled() {
			auto isFilled = m_curBuffer->getFreeSpaceSize() == 0;
			if (isFilled) {
				createNewBuffer();
			}
			return isFilled;
		}

		void clear() {
			for (auto it : m_buffers) {
				Buffer::Destroy(it);
			}
			m_buffers.clear();
			m_curBuffer = nullptr;
		}
	private:
		int m_size;
		Buffer* m_curBuffer = nullptr;
		Buffer::Stream m_bufferStream;
		std::list<Buffer*> m_buffers;

		void createNewBuffer() {
			m_buffers.push_back(m_curBuffer = Buffer::Create(m_size));
			m_bufferStream = Buffer::Stream(m_curBuffer);
			m_size *= 2;
		}
	};

	class Value
	{
	public:
		CE::DataTypePtr m_type = nullptr;
		uint64_t m_rawValue = 0;

		Value() = default;

		Value(CE::DataTypePtr type, uint64_t rawValue, void* rawData = nullptr)
			: m_type(type), m_rawValue(rawValue), m_rawData(rawData)
		{
			if (m_rawData != nullptr) {
				//mytodo: так можно?
				m_type = CE::DataType::GetUnit(m_type->getType(), "*");
			}
		}

		bool isString() const {
			return m_rawData != nullptr && m_type->isString();
		}

		void* getRawData() const {
			if (m_rawData == nullptr)
				return nullptr;
			return (void*)((std::uintptr_t)m_rawData + sizeof(USHORT));
		}

		USHORT getRawDataSize() {
			return *(USHORT*)m_rawData;
		}
	private:
		void* m_rawData = nullptr;
	};

	struct TimeData
	{
		typedef std::chrono::high_resolution_clock Clock;
		typedef std::chrono::time_point<std::chrono::steady_clock> TimePoint;
		TimePoint m_startTime;
		TimePoint m_endTime;

		TimeData()
		{
			m_startTime = Clock::now();
		}

		void setEndTime() {
			m_endTime = Clock::now();
		}

		float getElapsedTime() const {
			auto ns = m_endTime - m_startTime;
			return (float)ns.count() / 1000.0f;
		}
	};

	struct StatData
	{
		bool m_filterBefore;
		bool m_filterAfter = false;

		StatData(bool filterBefore = false)
			: m_filterBefore(filterBefore)
		{}
	};

	class TableLog
		: public Utils::Table<
			0,
			uint64_t, int, TimeData, std::list<Value>, Value, void*, StatData
		>
	{
	public:
		enum Columns {
			CallId,
			FunctionId,
			Time,
			ArgValues,
			RetValue,
			RetAddr,
			Stat
		};
		std::atomic<bool> m_enabled = true;

		TableLog(Function::Trigger* trigger)
			: m_trigger(trigger), m_allocator(1024 * 128)
		{}

		void addBeforeCallRow(CE::Hook::DynHook* hook, bool filter)
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

		void addAfterCallRow(CE::Hook::DynHook* hook, bool filter)
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

		std::list<Value> getArgValues(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
			std::list<Value> values;
			auto& argTypes = funcDef->getDeclaration().getSignature().getArgList();
			for (int argIdx = 1; argIdx <= min(hook->getArgCount(), argTypes.size()); argIdx++) {
				auto type = argTypes[argIdx - 1];
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

		Value getRetValue(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
			auto retType = funcDef->getDeclaration().getSignature().getReturnType();
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

		void getExtraValue(void* addrValue, CE::DataTypePtr argType, void*& dest) {
			do {
				dest = m_allocator.getStream().getNext();
				if (!Stat::Function::Record::CallInfoWriter::writeTypeValue(m_allocator.getStream(), addrValue, argType)) {
					dest = nullptr;
				}
			} while (m_allocator.isFilled());
		}

		void onClear() override {
			m_allocator.clear();
		}
	private:
		Function::Trigger* m_trigger;
		SeqAllocator m_allocator;
		std::mutex m_mutex;
	};
};