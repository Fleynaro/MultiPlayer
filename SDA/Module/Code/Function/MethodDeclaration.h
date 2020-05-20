#pragma once
#include "FunctionDeclaration.h"

namespace CE
{
	namespace DataType {
		class Class;
	};

	namespace Function
	{
		class MethodDecl : public FunctionDecl
		{
		public:
			MethodDecl(FunctionDeclManager* manager, DataType::Class* Class, DataType::Signature* signature, std::string name, std::string desc = "");

			MethodDecl(FunctionDeclManager* manager, DataType::Signature* signature, std::string name, std::string desc = "");

			void setClass(DataType::Class* Class);

			DataType::Class* getClass();

			Role getRole() override;

			void setRole(Role role);

			bool isVirtual();
		private:
			DataType::Class* m_class;
			Role m_role = Role::Method;
		};
	};
};