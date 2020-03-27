#pragma once
#include "Trigger.h"
#include "Utils/Table.h"
#include <chrono>

//MYTODO: addOwner и прочее можно юзать только для new аллокатора. Выход - умные указатели

namespace CE::Trigger::Function
{
	class SeqAllocator
	{
	public:
		SeqAllocator(int size)
			: m_size(size)
		{}

		~SeqAllocator() {
			for (auto it : m_buffers) {
				Buffer::Destroy(it);
			}
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
		CE::Type::Type* m_type = nullptr;
		uint64_t m_rawValue = 0;
		int m_rawDataSize = 0;
		void* m_rawData = nullptr;

		Value() = default;

		Value(CE::Type::Type* type, uint64_t rawValue, void* rawData = nullptr, int rawDataSize = 0)
			: m_type(type), m_rawValue(rawValue), m_rawData(rawData), m_rawDataSize(rawDataSize)
		{
			/*m_type->addOwner();*/
		}

		~Value() {
			/*if(m_type != nullptr)
				m_type->free();*/ //multiple times called
		}
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

		float getElapsedTime() {
			auto ns = m_endTime - m_startTime;
			return (float)ns.count() / 1000.0;
		}
	};

	class TableLog
		: public Utils::Table<
			0,
			uint64_t, int, TimeData, std::list<Value>, Value
		>
	{
	public:
		enum Columns {
			CallId,
			FunctionId,
			Time,
			ArgValues,
			RetValue
		};
		std::atomic<bool> m_enabled = true;

		TableLog(Function::Trigger* trigger)
			: m_trigger(trigger), m_allocator(1024 * 128)
		{}

		void addBeforeCallRow(CE::Hook::DynHook* hook)
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
				Value()
			);
			m_mutex.unlock();
		}

		void addAfterCallRow(CE::Hook::DynHook* hook)
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
		}

		std::list<Value> getArgValues(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
			using namespace CE::Type;
			std::list<Value> values;
			auto argTypes = funcDef->getDeclaration().getSignature().getArgList();
			for (int argIdx = 1; argIdx <= min(hook->getArgCount(), argTypes.size()); argIdx++) {
				auto type = argTypes[argIdx - 1];
				void* rawData = nullptr;
				int rawDataSize = 0;

				if (type->isPointer()) {
					getExtraValue((void*)hook->getArgumentValue(argIdx), type, rawData, rawDataSize);
				}

				values.push_back(
					Value(
						type,
						Function::GetArgumentValue(type, hook, argIdx),
						rawData,
						rawDataSize
					)
				);
			}
			return values;
		}

		Value getRetValue(CE::Function::FunctionDefinition* funcDef, CE::Hook::DynHook* hook) {
			using namespace CE::Type;
			auto retType = funcDef->getDeclaration().getSignature().getReturnType();
			void* rawData = nullptr;
			int rawDataSize = 0;

			if (retType->isPointer()) {
				getExtraValue((void*)hook->getReturnValue(), retType, rawData, rawDataSize);
			}

			return Value(
				retType,
				Function::GetReturnValue(retType, hook),
				rawData,
				rawDataSize
			);
		}

		void getExtraValue(void* addrValue, CE::Type::Type* argType, void*& dest, int& size) {
			do {
				dest = m_allocator.getStream().getNext<void>();
				if (Stat::Function::Record::CallInfoWriter::writeTypeValue(m_allocator.getStream(), addrValue, argType)) {
					size = static_cast<int>((std::uintptr_t)m_allocator.getStream().getNext<void>() - (std::uintptr_t)dest);
				}
				else {
					dest = nullptr;
					size = 0;
					break;
				}
			} while (m_allocator.isFilled());
		}
	private:
		Function::Trigger* m_trigger;
		SeqAllocator m_allocator;
		std::mutex m_mutex;
	};
};