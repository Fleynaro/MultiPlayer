#pragma once
#include "AbstractFilter.h"

namespace CE::Trigger::Function::Filter
{
	class Empty : public AbstractFilter
	{
	public:
		Empty() {}

		Id getId() override {
			return Id::Empty;
		}

		bool checkFilterBefore(CE::Hook::DynHook* hook) override {
			return true;
		}

		bool checkFilterAfter(CE::Hook::DynHook* hook) override {
			return true;
		}
	};

	class Object : public AbstractFilter
	{
	public:
		Object() = default;
		Object(void* addr)
			: m_addr(addr)
		{}

		Id getId() override {
			return Id::Object;
		}

		bool checkFilterBefore(CE::Hook::DynHook* hook) override {
			return hook->getArgumentValue<void*>(1) == m_addr;
		}

		void serialize(BitStream& bt)
		{
			Data data;
			data.m_addr = m_addr;
			bt.write(&data, sizeof(Data));
		}

		void deserialize(BitStream& bt)
		{
			Data data;
			bt.read(&data, sizeof(Data));
			m_addr = data.m_addr;
		}

		void* m_addr = nullptr;
	private:
		struct Data
		{
			void* m_addr;
		};				
	};
};