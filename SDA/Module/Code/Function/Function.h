#pragma once
#include "../Variable/Variable.h"

namespace CE
{
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

		using ArgNameList = std::vector<std::string>;

		class FunctionDecl : public Desc
		{
		public:
			FunctionDecl(int id, std::string name, std::string desc = "")
				: Desc(id, name, desc)
			{}

			virtual std::string getSigName() {
				std::string name = getSignature().getReturnType()->getDisplayName() + " " + getName() + "(";

				auto& argList = getSignature().getArgList();
				for (int i = 0; i < argList.size(); i++) {
					name += argList[i]->getDisplayName() + " " + getArgNameList()[i] + ", ";
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

			inline ArgNameList& getArgNameList() {
				return m_argNames;
			}

			virtual bool isMethod() {
				return false;
			}

			void addArgument(Type::Type* type, std::string name) {
				getSignature().getArgList().push_back(type);
				getArgNameList().push_back(name);
			}

			void changeArgument(int id, Type::Type* type, std::string name = "") {
				getSignature().getArgList()[id]->free();
				getSignature().getArgList()[id] = type;
				if (name.length() > 0) {
					m_argNames[id] = name;
				}
			}

			void removeLastArgument() {
				getSignature().getArgList().pop_back();
				m_argNames.pop_back();
			}

			void deleteAllArguments() {
				getSignature().getArgList().clear();
				getArgNameList().clear();
			}

			bool m_argumentsChanged = false;
		private:
			Signature m_signature;
			ArgNameList m_argNames;
		};




		class Method;
		class Function : public IGhidraUnit
		{
		public:
			using ArgList = std::vector<Variable::Param>;

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

			Function(void* addr, RangeList ranges, int func_id, FunctionDecl* decl)
				: m_addr(addr), m_ranges(ranges), m_id(func_id), m_decl(decl)
			{}

			Function(void* addr, RangeList ranges, int func_id, std::string name, std::string desc = "")
				: Function(addr, ranges, func_id, new FunctionDecl(func_id, name, desc))
			{}

			inline FunctionDecl& getDeclaration() {
				return *m_decl;
			}

			inline Signature& getSignature() {
				return getDeclaration().getSignature();
			}

			inline ArgNameList& getArgNameList() {
				return getDeclaration().getArgNameList();
			}

			int getId() {
				return m_id;
			}

			inline std::string getName() {
				return getDeclaration().getName();
			}

			inline std::string getDesc() {
				return getDeclaration().getDesc();
			}

			inline std::string getSigName() {
				return getDeclaration().getSigName();
			}

			inline bool isMethod() {
				return getDeclaration().isMethod();
			}

			virtual void call(ArgList args) {}

			void* getAddress() {
				return m_addr;
			}

			RangeList& getRangeList() {
				return m_ranges;
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

			Method* getMethodBasedOn();

			inline Trigger::Function::Hook* getHook() {
				return m_hook;
			}

			Trigger::Function::Hook* createHook();

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		protected:
			int m_id;
			void* m_addr;
			RangeList m_ranges;
			FunctionDecl* m_decl;
			Trigger::Function::Hook* m_hook = nullptr;
			bool m_ghidraUnit = true;
		};
	};
};