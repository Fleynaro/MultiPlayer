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
			~Signature() {
				if (m_returnType != nullptr)
					m_returnType->free();
			}

			void setReturnType(Type::Type* returnType) {
				if (m_returnType != nullptr)
					m_returnType->free();
				m_returnType = returnType;
				m_returnType->addOwner();
				//m_retTypeChanged = true;
			}

			Type::Type* getReturnType() {
				return m_returnType;
			}

			ArgTypeList& getArgList() {
				return m_args;
			}

			void addArgument(Type::Type* type) {
				type->addOwner();
				m_args.push_back(type);
			}

			void changeArgument(int id, Type::Type* type) {
				m_args[id]->free();
				type->addOwner();
				m_args[id] = type;
			}

			void removeLastArgument() {
				if (m_args.size() > 0)
					m_args[m_args.size() - 1]->free();
				m_args.pop_back();
			}

			void deleteAllArguments() {
				for (auto it : m_args) {
					it->free();
				}
				m_args.clear();
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
			enum class Role
			{
				Function,
				Method,
				StaticMethod,
				VirtualMethod,
				Constructor,
				Destructor,
				VirtualDestructor
			};

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

			virtual Role getRole() {
				return Role::Function;
			}

			bool isFunction() {
				return isFunction(getRole());
			}

			static bool isFunction(Role role) {
				return role == Role::Function;
			}

			void addArgument(Type::Type* type, const std::string& name) {
				getSignature().addArgument(type);
				getArgNameList().push_back(name);
			}

			void changeArgument(int id, Type::Type* type, const std::string& name = "") {
				getSignature().changeArgument(id, type);
				if (name.length() > 0) {
					m_argNames[id] = name;
				}
			}

			void removeLastArgument() {
				getSignature().removeLastArgument();
				m_argNames.pop_back();
			}

			void deleteAllArguments() {
				getSignature().deleteAllArguments();
				getArgNameList().clear();
			}

			bool m_argumentsChanged = false;
		private:
			Signature m_signature;
			ArgNameList m_argNames;
		};

		//class Method;
		class FunctionDefinition
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

			FunctionDefinition(void* addr, RangeList ranges, int def_id, FunctionDecl* decl)
				: m_addr(addr), m_ranges(ranges), m_id(def_id), m_decl(decl)
			{}

			int getId() {
				return m_id;
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

			//Method* getMethodBasedOn();

			inline Trigger::Function::Hook* getHook() {
				return m_hook;
			}

			inline bool hasHook() {
				return m_hook != nullptr;
			}

			void createHook();

			inline FunctionDecl* getDeclarationPtr() {
				return m_decl;
			}

			inline FunctionDecl& getDeclaration() {
				return *getDeclarationPtr();
			}
		protected:
			int m_id;
			void* m_addr;
			RangeList m_ranges;
			Trigger::Function::Hook* m_hook = nullptr;
			FunctionDecl* m_decl;
		};

		class Function : public IGhidraUnit
		{
		public:
			Function(FunctionDecl* decl, FunctionDefinition* def = nullptr)
				: m_decl(decl), m_def(def)
			{}

			Function(FunctionDefinition* def)
				: m_def(def), m_decl(def->getDeclarationPtr())
			{}

			inline FunctionDecl& getDeclaration() {
				return *m_decl;
			}

			inline FunctionDefinition& getDefinition() {
				return *m_def;
			}

			bool hasDefinition() {
				return m_def != nullptr;
			}

			inline int getId() {
				if (!hasDefinition())
					0;
				return getDefinition().getId();
			}

			inline void* getAddress() {
				if (!hasDefinition())
					nullptr;
				return getDefinition().getAddress();
			}

			inline Signature& getSignature() {
				return getDeclaration().getSignature();
			}

			inline ArgNameList& getArgNameList() {
				return getDeclaration().getArgNameList();
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

			inline bool isFunction() {
				return getDeclaration().isFunction();
			}

			bool isGhidraUnit() override {
				return m_ghidraUnit;
			}

			void setGhidraUnit(bool toggle) override {
				m_ghidraUnit = toggle;
			}
		protected:
			FunctionDecl* m_decl;
			FunctionDefinition* m_def;
			bool m_ghidraUnit = true;
		};
	};
};