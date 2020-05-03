#pragma once
#include <Code/Function/FunctionDeclaration.h>
#include <Code/Function/MethodDeclaration.h>

/*
	1) сделать менеджер, зависимым от IRepository и абстрактного менеджера итемов
	2) сделать транзакции
*/

namespace CE {
	class FunctionDeclManager;
};

namespace DB
{
	class FunctionDeclMapper : public AbstractMapper
	{
	public:
		FunctionDeclMapper(IRepository* repository);

		void loadAll();

		CE::FunctionDeclManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void loadFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl);

		void saveFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl);

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Function::FunctionDecl& decl);
	};
};