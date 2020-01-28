#pragma once
#include "Function.h"

namespace CE
{
	namespace Type {
		class Class;
	};

	namespace Function
	{
		class MethodDecl : public FunctionDecl
		{
		public:
			MethodDecl(Type::Class* Class, int id, std::string name, std::string desc = "")
				: m_class(Class), FunctionDecl(id, name, desc)
			{}

			MethodDecl(int id, std::string name, std::string desc = "")
				: MethodDecl(nullptr, id, name, desc)
			{}

			std::string getSigName() override {
				return (isVirtual() ? "virtual " : "") + FunctionDecl::getSigName();
			}

			std::string getName() override;

			void setClass(Type::Class* Class);

			Type::Class* getClass() {
				return m_class;
			}

			bool isMethod() override {
				return true;
			}

			bool isConstructor() {
				return m_constructor;
			}

			bool isVirtual() {
				return m_virtual;
			}
		private:
			Type::Class* m_class;
			bool m_constructor = false;
			bool m_virtual = false;
		};

		class Method : public Function
		{
		public:
			Method(void* addr, RangeList ranges, int func_id, MethodDecl* decl)
				: Function(addr, ranges, func_id, decl)
			{}

			Method(void* addr, RangeList ranges, int func_id, std::string name, std::string desc = "")
				: Method(addr, ranges, func_id, new MethodDecl(func_id, name, desc))
			{}

			virtual void call(ArgList args) {}

			inline MethodDecl& getDeclaration() {
				return static_cast<MethodDecl&>(Function::getDeclaration());
			}

			inline Type::Class* getClass() {
				return getDeclaration().getClass();
			}

			inline void setClass(Type::Class* Class) {
				return getDeclaration().setClass(Class);
			}

			Function* getFunctionBasedOn() {
				auto func = new Function(m_addr, m_ranges, getId(), getName(), getDesc());
				func->getArgNameList().swap(getArgNameList());
				func->getSignature().getArgList().swap(getSignature().getArgList());
				func->getSignature().setReturnType(getSignature().getReturnType());
				return func;
			}
		};
	};
};