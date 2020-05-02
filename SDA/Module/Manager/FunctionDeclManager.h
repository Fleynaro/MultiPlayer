#pragma once
#include "AbstractManager.h"
#include <Code/Function/MethodDeclaration.h>

namespace DB {
	class FunctionDeclMapper;
};

namespace CE
{
	class FunctionDeclManager : public AbstractItemManager
	{
	public:
		FunctionDeclManager(ProgramModule* module);

		void loadFunctionDecls();

		Function::FunctionDecl* createFunctionDecl(std::string name, std::string desc = "");

		Function::MethodDecl* createMethodDecl(std::string name, std::string desc = "");

		Function::FunctionDecl* getFunctionDeclById(DB::Id id);

	private:
		DB::FunctionDeclMapper* m_funcDeclMapper;
	};
};