#pragma once
#include "FunctionDeclaration.h"

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
			MethodDecl(FunctionDeclManager* manager, Type::Class* Class, std::string name, std::string desc = "");

			MethodDecl(FunctionDeclManager* manager, std::string name, std::string desc = "");

			std::string getSigName() override;

			std::string getName() override;

			void setClass(Type::Class* Class);

			Type::Class* getClass();

			Role getRole() override;

			void setRole(Role role);

			bool isVirtual();
		private:
			Type::Class* m_class;
			Role m_role = Role::Method;
		};
	};
};