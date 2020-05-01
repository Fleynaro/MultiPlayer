#pragma once
#include "AbstractManager.h"
#include <Code/Function/MethodDeclaration.h>

namespace CE
{
	class FunctionDeclManager : public AbstractItemManager
	{
	public:
		FunctionDeclManager(ProgramModule* module);

		Function::FunctionDecl* createFunctionDecl(std::string name, std::string desc = "");

		Function::MethodDecl* createMethodDecl(std::string name, std::string desc = "");

		Function::FunctionDecl* getFunctionDeclById(DB::Id id);
	};
};