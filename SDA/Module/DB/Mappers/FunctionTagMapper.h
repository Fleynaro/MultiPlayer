#pragma once
#include <DB/AbstractMapper.h>
#include <FunctionTag/FunctionTagCollection.h>

namespace CE {
	class FunctionTagManager;
};

namespace DB
{
	class FunctionUserTagMapper : public AbstractMapper
	{
	public:
		FunctionUserTagMapper(CE::FunctionTagManager* manager);

		void loadAll();

		Id getNextId();

		IDomainObject* doLoad(Database* db, SQLite::Statement& query);

		CE::FunctionTagManager* getManager();
	protected:
		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Function::Tag::UserTag& tag);
	};
};