#pragma once
#include <Code/Code.h>
#include <DynHook/DynHook.h>
#include <Address/Address.h>
#include <Utils/BufferStreamRecorder.h>

namespace CE::Trigger::Function
{
	class Trigger;
};

namespace CE::Stat::Function::Record
{
	enum class Type {
		BeforeCallInfo,
		AfterCallInfo
	};

	struct Header {
		BYTE m_type;
		uint64_t m_uid;
		int m_triggerId;
		int m_funcDefId;
	};

	class CallInfoWriter : public StreamRecordWriter
	{
	public:
		CallInfoWriter(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
			: m_trigger(trigger), m_hook(hook)
		{}

		void writeHeader(Type type);

		static bool writeTypeValue(Buffer::Stream& bufferStream, void* argAddrValue, CE::Type::Type* argType);
	protected:
		CE::Trigger::Function::Trigger* m_trigger;
		CE::Hook::DynHook* m_hook;

		CE::Function::FunctionDefinition* getFunctionDef();
	};
};