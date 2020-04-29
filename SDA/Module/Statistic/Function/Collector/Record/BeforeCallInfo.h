#pragma once
#include "CallInfoWriter.h"

namespace CE::Stat::Function::Record::BeforeCallInfo
{
	struct ArgHeader {
		uint64_t m_argExtraBits;
		BYTE m_argCount;
	};
	using ArgBody = BYTE;


	class Writer : public CallInfoWriter
	{
	public:
		Writer(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook);

		void write() override;

	private:
		void writeArgument(int argIdx);

		void writeArgumentExtra(int argIdx, void* argAddrValue);
	private:
		ArgHeader* m_argHeader;
	};


	class Reader
	{
	public:
		struct ArgInfo {
			uint64_t m_value;
			uint64_t m_xmmValue;
			USHORT m_extraDataSize = 0;
			BYTE* m_extraData = nullptr;
			bool m_hasXmmValue = false;
		};

		Reader(Buffer::Stream* bufferStream);

		ArgInfo readArgument();

		ArgHeader& getArgHeader();
	private:
		Buffer::Stream m_bufferStream;
		ArgHeader* m_argHeader;
		int m_curArgIdx = 1;

		Buffer::Stream& getStream();
	};
};