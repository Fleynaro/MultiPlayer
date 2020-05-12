#pragma once
#include <DB/AbstractMapper.h>

namespace CE {
	class ProccessModule;
	class ProcessModuleManager;
};

namespace DB
{
	class ProcessModuleMapper : public AbstractMapper
	{
	public:
		ProcessModuleMapper(CE::ProcessModuleManager* manager);

		void loadAll();

		Id getNextId() override;

		CE::ProcessModuleManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::ProccessModule& module);
	};
};