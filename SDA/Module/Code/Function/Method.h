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

			Role getRole() override {
				return m_role;
			}

			void setRole(Role role) {
				m_role = role;
			}

			bool isVirtual() {
				return getRole() == Role::VirtualMethod || getRole() == Role::VirtualDestructor;
			}
		private:
			Type::Class* m_class;
			Role m_role = Role::Method;
		};

		/*class AbstractMethod : public AbstractFunction
		{
		public:
			AbstractMethod(MethodDecl* decl)
				: AbstractFunction(decl)
			{}

			inline MethodDecl& getDeclaration() {
				return static_cast<MethodDecl&>(AbstractFunction::getDeclaration());
			}

			inline Type::Class* getClass() {
				return getDeclaration().getClass();
			}

			inline void setClass(Type::Class* Class) {
				return getDeclaration().setClass(Class);
			}
		};
		*/

		class Method : public Function
		{
		public:
			Method(FunctionDecl* decl, FunctionDefinition* def = nullptr)
				: Function(decl, def)
			{}

			Method(FunctionDefinition* def)
				: Function(def)
			{}
			
			inline MethodDecl& getDeclaration() {
				return static_cast<MethodDecl&>(Function::getDeclaration());
			}

			inline Type::Class* getClass() {
				return getDeclaration().getClass();
			}

			inline void setClass(Type::Class* Class) {
				return getDeclaration().setClass(Class);
			}

			/*Function* getFunctionBasedOn() {
				auto func = new Function(m_addr, m_ranges, getId(), getName(), getDesc());
				func->getArgNameList().swap(getArgNameList());
				func->getSignature().getArgList().swap(getSignature().getArgList());
				func->getSignature().setReturnType(getSignature().getReturnType());
				return func;
			}*/
		};
	};
};