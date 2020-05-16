#pragma once
#include "GhidraDataPacket.h"
#include <SQLiteCpp/SQLiteCpp.h>

namespace CE::Ghidra
{
	struct SyncContext
	{
		int m_syncId;
		DataPacket* m_dataPacket;
		SQLite::Database* m_db;
	};

	class IMapper
	{
	public:
		virtual void load(DataPacket* dataPacket) = 0;
		virtual void upsert(SyncContext* ctx, IObject* obj) = 0;
		virtual void remove(SyncContext* ctx, IObject* obj) = 0;
	};
};