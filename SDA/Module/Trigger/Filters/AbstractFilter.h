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

			virtual bool checkFilterBefore(CE::Hook::DynHook* hook);

			virtual bool checkFilterAfter(CE::Hook::DynHook* hook);

			virtual void serialize(BitStream& bt) {};

			virtual void deserialize(BitStream& bt) {};

			void setBeforeDefaultFilter(bool toggle);

			void setAfterDefaultFilter(bool toggle);
		private:
			bool m_beforeDefFilter = false;
			bool m_afterDefFilter = false;
		};
	};

	uint64_t GetArgumentValue(CE::DataTypePtr type, CE::Hook::DynHook* hook, int argIdx);

	uint64_t GetReturnValue(CE::DataTypePtr type, CE::Hook::DynHook* hook);
};