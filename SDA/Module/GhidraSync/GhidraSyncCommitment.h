#pragma once
#include "GhidraAbstractMapper.h"

namespace CE::Ghidra
{
	class SyncCommitment
	{
	public:
		SyncCommitment(SQLite::Database* db, DataPacketTransferProvider* provider);

		void upsert(IObject* obj);

		void remove(IObject* obj);

		void commit();
		
	private:
		SQLite::Database* m_db;
		DataPacketTransferProvider* m_provider;
		std::list<IObject*> m_upsertedObjs;
		std::list<IObject*> m_removedObjs;

		int createSyncRecord();
	};
};