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
			static uint64_t GetArgumentValue(CE::Type::Type* type, CE::Hook::DynHook* hook, int argIdx) {
				using namespace CE::Type;
				if (auto sysType = dynamic_cast<SystemType*>(type->getBaseType(true, false))) {
					if (argIdx <= 4 && sysType->getSet() == SystemType::Real)
						return hook->getXmmArgumentValue(argIdx);
				}
				return hook->getArgumentValue(argIdx);
			}

			static uint64_t GetReturnValue(CE::Type::Type* type, CE::Hook::DynHook* hook) {
				using namespace CE::Type;
				if (auto sysType = dynamic_cast<SystemType*>(type->getBaseType(true, false))) {
					if (sysType->getSet() == SystemType::Real)
						return hook->getXmmReturnValue();
				}
				return hook->getReturnValue();
			}

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

				class ICompositeFilter : public IFilter
				{
				public:
					ICompositeFilter(std::list<IFilter*> filters = {})
						: m_filters(filters)
					{}

					~ICompositeFilter() {
						for (auto filter : m_filters) {
							delete filter;
						}
					}

					void serialize(BitStream& bt)
					{
						bt.write(static_cast<int>(m_filters.size()));
					}

					void deserialize(BitStream& bt)
					{
						m_filtersSavedCount = bt.read<int>();
					}

					void addFilter(IFilter* filter) {
						m_filters.push_back(filter);
					}

					void removeFilter(IFilter* filter) {
						m_filters.remove(filter);
						delete filter;
					}

					auto& getFilters() {
						return m_filters;
					}

					int m_filtersSavedCount = -1;
				protected:
					std::list<IFilter*> m_filters;
				};

				class ConditionFilter : public ICompositeFilter
				{
				public:
					ConditionFilter(Id id, std::list<IFilter*> filters = {})
						: m_id(id), ICompositeFilter(filters)
					{
						switch (id)
						{
						case Id::Condition_AND:
							m_source = true;
							m_cmp = [](bool a, bool b) { return a & b; };
							break;
						case Id::Condition_OR:
							m_source = false;
							m_cmp = [](bool a, bool b) { return a | b; };
							break;
						case Id::Condition_XOR:
							m_source = false;
							m_cmp = [](bool a, bool b) { return a ^ b; };
							break;
						case Id::Condition_NOT:
							m_cmp = [](bool a, bool b) { return 1 ^ b; };
							break;
						}
					}

					Id getId() override {
						return m_id;
					}

					bool checkFilterBefore(CE::Hook::DynHook* hook) override {
						bool result = m_source;
						for (auto filter : m_filters) {
							result = m_cmp(result, filter->checkFilterBefore(hook));
						}
						return result;
					}

					bool checkFilterAfter(CE::Hook::DynHook* hook) override {
						bool result = m_source;
						for (auto filter : m_filters) {
							result = m_cmp(result, filter->checkFilterAfter(hook));
						}
						return result;
					}

				private:
					Id m_id;
					bool m_source;
					std::function<bool(bool, bool)> m_cmp;
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

					void* m_addr = nullptr;
				private:
					struct Data
					{
						void* m_addr;
					};				
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
						if (!type->isPointer()) {
							switch (type->getBaseType()->getId())
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
						return cmp(static_cast<uint64_t>(op1), static_cast<uint64_t>(op2), operation);
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
							auto& argList = function->getDeclaration().getSignature().getArgList();
							if (m_argId > argList.size())
								return false;

							auto type = argList[m_argId - 1];
							return cmp(
								GetArgumentValue(type, hook, m_argId),
								m_value,
								m_operation,
								type
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

						int m_argId = 1;
						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
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
								GetReturnValue(type, hook),
								m_value,
								m_operation,
								type
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

						uint64_t m_value = 0;
						Operation m_operation = Operation::Eq;
					private:
						struct Data
						{
							int m_argId;
							uint64_t m_value;
							Operation m_operation;
						};
					};
				};
			};
		};
	};

	namespace TreeNodeInfo
	{
		struct TreeNode {
			std::string m_name;
			std::string m_desc;

			TreeNode(const std::string& name, const std::string& desc)
				: m_name(name), m_desc(desc)
			{}

			virtual ~TreeNode() {}
		};

		struct Category : public TreeNode {
			std::list<TreeNode*> m_nodes;

			Category(const std::string& name, const std::string& desc, std::list<TreeNode*> nodes = {})
				: TreeNode(name, desc), m_nodes(nodes)
			{}
		};

		template<class T1, typename T2>
		static T1* GetFilter_(T2 id, TreeNode* node) {
			if (T1* filter = dynamic_cast<T1*>(node)) {
				if (filter->m_id == id)
					return filter;
			}
			if (Category* category = dynamic_cast<Category*>(node)) {
				for (auto it : category->m_nodes) {
					if (T1* filter = GetFilter_<T1, T2>(id, it)) {
						return filter;
					}
				}
			}
			return nullptr;
		}
	};

	namespace TriggerFilterInfo
	{
		using namespace TreeNodeInfo;

		namespace Function
		{
			using namespace Trigger::Function::Filter;

			struct Filter : public TreeNode {
				Id m_id;
				std::function<IFilter * ()> m_createFilter;

				Filter(Id id, const std::function<IFilter * ()>& createFilter, const std::string& name, const std::string& desc = "")
					: m_id(id), m_createFilter(createFilter), TreeNode(name, desc)
				{}
			};

			static inline Category* RootCategory =
				new Category("Filters", "", {
					new Category("Condition", "", {
						new Filter(Id::Condition_AND, []() { return new ConditionFilter(Id::Condition_AND); }, "AND"),
						new Filter(Id::Condition_OR, []() { return new ConditionFilter(Id::Condition_OR); }, "OR"),
						new Filter(Id::Condition_XOR, []() { return new ConditionFilter(Id::Condition_XOR); }, "XOR"),
						new Filter(Id::Condition_NOT, []() { return new ConditionFilter(Id::Condition_NOT); }, "NOT")
					}),
					new Filter(Id::Empty, []() { return new Empty; }, "Empty"),
					new Filter(Id::Object, []() { return new Object; }, "Object"),
					new Filter(Id::Argument, []() { return new Cmp::Argument; }, "Argument"),
					new Filter(Id::ReturnValue, []() { return new Cmp::RetValue; }, "Return value")
					});

			static Filter* GetFilter(Id id) {
				return GetFilter_<Filter>(id, RootCategory);
			}
		};
	};
};