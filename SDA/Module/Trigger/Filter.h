#pragma once
#include <DynHook/DynHook.h>
#include <Code/Code.h>
#include <Utils/BitStream.h>

namespace CE
{
	namespace Trigger
	{
		namespace Function
		{
			class Hook;
			namespace Filter
			{
				enum class Id
				{
					Empty,
					Object,
					Argument,
					ReturnValue
				};

				class IFilter
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

				class Empty : public IFilter
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

				class Object : public IFilter
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
				private:
					struct Data
					{
						void* m_addr;
					};

					void* m_addr = nullptr;
				};

				namespace Cmp
				{
					enum Operation
					{
						Eq,
						Neq,
						Lt,
						Le,
						Gt,
						Ge
					};

					template<typename T>
					static bool cmp(T op1, T op2, Operation operation)
					{
						switch (operation)
						{
						case Operation::Eq: return op1 == op2;
						case Operation::Neq: return op1 != op2;
						case Operation::Lt: return op1 < op2;
						case Operation::Le: return op1 <= op2;
						case Operation::Gt: return op1 > op2;
						case Operation::Ge: return op1 >= op2;
						}
						return false;
					}

					static bool cmp(uint64_t op1, uint64_t op2, Operation operation, CE::Type::Type* type)
					{
						using namespace CE::Type;
						if (type->getGroup() == CE::Type::Type::Simple) {
							switch (SystemType::GetBasicTypeOf(type))
							{
							case SystemType::Bool:
							case SystemType::Byte:
								return cmp(static_cast<BYTE>(op1), static_cast<BYTE>(op2), operation);
							case SystemType::Int8:
								return cmp(static_cast<int8_t>(op1), static_cast<int8_t>(op2), operation);
							case SystemType::Int16:
								return cmp(static_cast<int16_t>(op1), static_cast<int16_t>(op2), operation);
							case SystemType::Int32:
								return cmp(static_cast<int32_t>(op1), static_cast<int32_t>(op2), operation);
							case SystemType::Int64:
								return cmp(static_cast<int64_t>(op1), static_cast<int64_t>(op2), operation);
							case SystemType::UInt16:
							case SystemType::UInt32:
							case SystemType::UInt64:
								return cmp(static_cast<uint64_t>(op1), static_cast<uint64_t>(op2), operation);
							case SystemType::Float:
								return cmp(reinterpret_cast<float&>(op1), reinterpret_cast<float&>(op2), operation);
							case SystemType::Double:
								return cmp(reinterpret_cast<double&>(op1), reinterpret_cast<double&>(op2), operation);
							}
						}
						return false;
					}

					class Argument : public IFilter
					{
					public:

						Argument() = default;
						Argument(int argId, uint64_t value, Operation operation)
							: m_argId(argId), m_value(value), m_operation(operation)
						{}

						Id getId() override {
							return Id::Argument;
						}

						bool checkFilterBefore(CE::Hook::DynHook* hook) override {
							using namespace CE::Type;

							auto function = (CE::Function::FunctionDefinition*)hook->getUserPtr();
							auto type = function->getDeclaration().getSignature().getArgList()[m_argId - 1];
							return cmp(
								SystemType::GetNumberSetOf(type) == SystemType::Real ? hook->getXmmArgumentValue(m_argId) : hook->getArgumentValue(m_argId),
								m_value,
								m_operation
							);
						}

						template<typename T = uint64_t>
						void setValue(T value) {
							(T&)m_value = value;
						}

						void setOperation(Operation operation) {
							m_operation = operation;
						}

						void serialize(BitStream& bt)
						{
							Data data;
							data.m_argId = m_argId;
							data.m_value = m_value;
							data.m_operation = m_operation;
							bt.write(&data, sizeof(Data));
						}

						void deserialize(BitStream& bt)
						{
							Data data;
							bt.read(&data, sizeof(Data));
							m_argId = data.m_argId;
							m_value = data.m_value;
							m_operation = data.m_operation;
						}
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
						int m_argId = 0;
						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					};

					class RetValue : public IFilter
					{
					public:
						RetValue() = default;
						RetValue(uint64_t value, Operation operation)
							: m_value(value), m_operation(operation)
						{}

						Id getId() override {
							return Id::ReturnValue;
						}

						bool checkFilterAfter(CE::Hook::DynHook* hook) override {
							using namespace CE::Type;

							auto function = (CE::Function::Function*)hook->getUserPtr();
							auto type = function->getSignature().getReturnType();
							return cmp(
								SystemType::GetNumberSetOf(type) == SystemType::Real ? hook->getXmmReturnValue() : hook->getReturnValue(),
								m_value,
								m_operation
							);
						}

						template<typename T = uint64_t>
						void setValue(T value) {
							(T&)m_value = value;
						}

						void setOperation(Operation operation) {
							m_operation = operation;
						}

						void serialize(BitStream& bt)
						{
							Data data;
							data.m_value = m_value;
							data.m_operation = m_operation;
							bt.write(&data, sizeof(Data));
						}

						void deserialize(BitStream& bt)
						{
							Data data;
							bt.read(&data, sizeof(Data));
							m_value = data.m_value;
							m_operation = data.m_operation;
						}
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					};
				};
			};
		};
	};
};