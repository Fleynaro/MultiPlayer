#pragma once
#include "FunctionTrigger.h"
#include "Utils/Table.h"
#include <chrono>

namespace CE::Trigger::Function
{
	class SeqAllocator
	{
	public:
		SeqAllocator(int size);

		~SeqAllocator();

		Buffer::Stream& getStream();

		bool isFilled();

		void clear();
	private:
		int m_size;
		Buffer* m_curBuffer = nullptr;
		Buffer::Stream m_bufferStream;
		std::list<Buffer*> m_buffers;

		void createNewBuffer();
	};

	class Value
	{
	public:
		CE::DataTypePtr m_type = nullptr;
		uint64_t m_rawValue = 0;

		Value() = default;

		Value(CE::DataTypePtr type, uint64_t rawValue, void* rawData = nullptr);

		bool isString() const;

		void* getRawData() const;

		USHORT getRawDataSize();
	private:
		void* m_rawData = nullptr;
	};

	struct TimeData
	{
		typedef std::chrono::high_resolution_clock Clock;
		typedef std::chrono::time_point<std::chrono::steady_clock> TimePoint;
		TimePoint m_startTime;
		TimePoint m_endTime;

		TimeData();

		void setEndTime();

		float getElapsedTime() const;
	};

	struct StatData
	{
		bool m_filterBefore;
		bool m_filterAfter = false;

		StatData(bool filterBefore = false);
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

		TableLog(Function::Trigger* trigger);

		void addBeforeCallRow(CE::Hook::DynHook* hook, bool filter);

		void addAfterCallRow(CE::Hook::DynHook* hook, bool filter);

		std::list<Value> getArgValues(CE::Function* funcDef, CE::Hook::DynHook* hook);

		Value getRetValue(CE::Function* funcDef, CE::Hook::DynHook* hook);

		void getExtraValue(void* addrValue, CE::DataTypePtr argType, void*& dest);

		void onClear() override;
	private:
		Function::Trigger* m_trigger;
		SeqAllocator m_allocator;
		std::mutex m_mutex;
	};
};