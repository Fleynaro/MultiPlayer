#pragma once
#include "../Variable/Variable.h"

namespace CE
{
	namespace CallGraph
	{
		class FunctionBody;
	};

	namespace Trigger::Function
	{
		class Hook;
	};

	namespace Function
	{
		class Signature
		{
		public:
			using ArgTypeList = std::vector<Type::Type*>;

			Signature() {}

			void setReturnType(Type::Type* returnType) {
				m_returnType = returnType;
				//m_retTypeChanged = true;
			}

			Type::Type* getReturnType() {
				return m_returnType;
			}

			ArgTypeList& getArgList() {
				return m_args;
			}

			//bool m_retTypeChanged = false;
		private:
			ArgTypeList m_args;
			Type::Type* m_returnType = nullptr;
		};

		class Method;
		class Function : public Desc, public IGhidraUnit
		{
		public:
			using ArgList = std::vector<Variable::Param>;
			using ArgNameList = std::vector<std::string>;

			class Range
			{
			public:
				Range() = default;
				Range(void* min_addr, void* max_addr)
					: m_min_addr(min_addr), m_max_addr(max_addr)
				{}
				Range(void* entry_addr, int size)
					: m_min_addr(entry_addr), m_max_addr((void*)((std::uintptr_t)entry_addr + size))
				{}

				bool isContainingAddress(void* addr) {
					return (std::uintptr_t)addr >= (std::uintptr_t)getMinAddress() && (std::uintptr_t)addr <= (std::uintptr_t)getMaxAddress();
				}

				std::uintptr_t getSize() {
					return (std::uintptr_t)getMaxAddress() - (std::uintptr_t)getMinAddress();
				}

				void* getMinAddress() {
					return m_min_addr;
				}

				void* getMaxAddress() {
					return m_max_addr;
				}
			private:
				void* m_min_addr = nullptr;
				void* m_max_addr = nullptr;
			};

			using RangeList = std::vector<Range>;

			Function(void* addr, RangeList ranges, int id, std::string name, std::string desc = "")
				: m_addr(addr), m_ranges(ranges), Desc(id, name, desc)
			{}

			virtual std::string getSigName() {
				std::string name = getSignature().getReturnType()->getName() + " " + getName() + "(";

				auto& argList = getSignature().getArgList();
				for (int i = 0; i < argList.size(); i++) {
					name += argList[i]->getName() + " " + getArgNameList()[i] + ", ";
				}
				if (argList.size() > 0) {
					name.pop_back();
					name.pop_back();
				}
				return name + ")";
			}

			inline Signature& getSignature() {
				return m_signature;
			}

			virtual bool isMethod() {
				return false;
			}

			virtual void call(ArgList args) {}

			void* getAddress() {
				return m_addr;
			}

			RangeList& getRangeList() {
				return m_ranges;
			}

			CallGraph::FunctionBody* getBody() {
				return m_funcBody;
			}

			void setBody(CallGraph::FunctionBody* body) {
				m_funcBody = body;
			}

			inline ArgNameList& getArgNameList() {
				return m_argNames;
			}

			void addRange(Range range) {
				m_ranges.push_back(range);
			}

			bool isContainingAddress(void* addr) {
				for (auto& range : m_ranges) {
					if (range.isContainingAddress(addr)) {
						return true;
					}
				}
				return false;
			}

			void addArgument(Type::Type* type, std::string name) {
				getSignature().getArgList().push_back(type);
				getArgNameList().push_back(name);
				m_argumentsChanged = true;
			}

			void changeArgument(int id, Type::Type* type, std::string name = "") {
				getSignature().getArgList()[id]->free();
				getSignature().getArgList()[id] = type;
				if (name.length() > 0) {
					m_argNames[id] = name;
				}
				m_argumentsChanged = true;
			}

			void removeLastArgument() {
				getSignature().getArgList().pop_back();
				m_argNames.pop_back();
				m_argumentsChanged = true;
			}

			void deleteAllArguments() {
				getSignature().getArgList().clear();
				getArgNameList().clear();
			}

			Method* getMethodBasedOn();

			inline Trigger::Function::Hook* getHook() {
				return m_hook;
			}

			Trigger::Function::Hook* createHook();

			bool m_argumentsChanged = false;

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		protected:
			void* m_addr;
			RangeList m_ranges;
			Signature m_signature;
			ArgNameList m_argNames;
			Trigger::Function::Hook* m_hook = nullptr;
			CallGraph::FunctionBody* m_funcBody = nullptr;
			bool m_ghidraUnit = true;
		};
	};
};