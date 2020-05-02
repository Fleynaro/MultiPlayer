#pragma once
#include <DynHook/DynHook.h>
#include <Code/Code.h>
#include <Utils/BitStream.h>

namespace CE::Trigger::Function
{
	class Hook;
	namespace Filter
	{
		enum class Id
		{
			Condition_AND,
			Condition_OR,
			Condition_XOR,
			Condition_NOT,
			Empty,
			Object,
			Argument,
			ReturnValue
		};

		class AbstractFilter
		{
		public:
			virtual Id getId() = 0;

			virtual bool checkFilterBefore(CE::Hook::DynHook* hook) {
				return m_beforeDefFilter;
			}
			virtual bool checkFilterAfter(CE::Hook::DynHook* hook) {
				return m_afterDefFilter;
			}

			virtual void serialize(BitStream& bt) {};
			virtual void deserialize(BitStream& bt) {};

			void setBeforeDefaultFilter(bool toggle) {
				m_beforeDefFilter = toggle;
			}

			void setAfterDefaultFilter(bool toggle) {
				m_afterDefFilter = toggle;
			}
		private:
			bool m_beforeDefFilter = false;
			bool m_afterDefFilter = false;
		};
	};

	static uint64_t GetArgumentValue(CE::DataType::Type* type, CE::Hook::DynHook* hook, int argIdx) {
		using namespace CE::DataType;
		if (auto sysType = dynamic_cast<SystemType*>(type->getBaseType(true, false))) {
			if (argIdx <= 4 && sysType->getSet() == SystemType::Real)
				return hook->getXmmArgumentValue(argIdx);
		}
		return hook->getArgumentValue(argIdx);
	}

	static uint64_t GetReturnValue(CE::DataType::Type* type, CE::Hook::DynHook* hook) {
		using namespace CE::DataType;
		if (auto sysType = dynamic_cast<SystemType*>(type->getBaseType(true, false))) {
			if (sysType->getSet() == SystemType::Real)
				return hook->getXmmReturnValue();
		}
		return hook->getReturnValue();
	}
};