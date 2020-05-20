#pragma once
#include <Code/Function/FunctionDeclaration.h>
#include <Code/Function/MethodDeclaration.h>

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

		Id getNextId() override;

		CE::FunctionDeclManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Function::FunctionDecl& decl);
	};
};